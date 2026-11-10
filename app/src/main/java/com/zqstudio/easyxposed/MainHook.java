package com.zqstudio.easyxposed;

import android.annotation.SuppressLint;
import android.net.IpPrefix;
import android.net.VpnService;
import android.os.Build;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.WeakHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 思路：
 * 1. addAllowedApplication 全部吞掉；addDisallowedApplication 只放行对自己的排除
 *    -> 名单为空 = 全局 VPN。
 * 2. establish 前：自排除（防回环）+ excludeRoute（API 33+）。
 * 3. 路由表优先从模块 APK 的 assets/cn_routes.txt 读取（一行一个 CIDR，支持 IPv4/IPv6），
 *    没有则回退到内置的粗粒度列表。
 * 4. 记录 VPN 自己的 TUN 地址 / DNS，凡是包含这些地址的排除段一律跳过，避免 DNS 或回环失效。
 *
 * 需要 compileSdk >= 33。LSPosed 作用域只勾选目标 VPN App。
 */
public class MainHook implements IXposedHookZygoteInit, IXposedHookLoadPackage {

    private static final String TAG = "[ForceGlobal] ";
    private static final String ASSET_ROUTES = "assets/cn_routes.txt";

    /** 局域网 / 私有地址（IPv4 + IPv6） */
    private static final String[] PRIVATE_ROUTES = {
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16",
            "fc00::/7", "fe80::/10"
    };

    /** 回退用：精确网段 */
    private static final String[] FALLBACK_PRECISE = {
            "1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19",
            "14.16.0.0/12", "27.8.0.0/13", "27.16.0.0/12",
            "49.4.0.0/14", "49.64.0.0/11"
    };

    /** 回退用：粗粒度 /8（并非全是国内地址，仅作没有 cn_routes.txt 时的兜底） */
    private static final int[] FALLBACK_SLASH8 = {
            36, 39, 42, 58, 59, 60, 61, 101, 103, 106,
            110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
            120, 121, 122, 123, 124, 125,
            139, 140, 144, 150, 153, 157, 163, 171, 175,
            180, 182, 183, 202, 203, 210, 211,
            218, 219, 220, 221, 222, 223
    };

    // ---------------------------------------------------------------- 状态

    private volatile String modulePath;
    private volatile String selfPackage;
    private List<Route> routes; // 懒加载，受 this 锁保护

    private static final class Route {
        final InetAddress addr;
        final int len;

        Route(InetAddress addr, int len) {
            this.addr = addr;
            this.len = len;
        }

        boolean contains(InetAddress a) {
            byte[] x = addr.getAddress();
            byte[] y = a.getAddress();
            if (x.length != y.length) return false;
            int full = len / 8;
            int rem = len % 8;
            for (int i = 0; i < full; i++) {
                if (x[i] != y[i]) return false;
            }
            if (rem > 0) {
                int mask = (0xFF << (8 - rem)) & 0xFF;
                return (x[full] & mask) == (y[full] & mask);
            }
            return true;
        }
    }

    /** 每个 Builder 一份：TUN 地址 / DNS，以及是否已处理过 */
    private static final class State {
        private final List<InetAddress> local = new ArrayList<>();
        private boolean done;

        synchronized void add(InetAddress a) {
            if (!local.contains(a)) local.add(a);
        }

        synchronized boolean overlaps(Route r) {
            for (InetAddress a : local) {
                if (r.contains(a)) return true;
            }
            return false;
        }

        synchronized boolean markDone() {
            if (done) return false;
            done = true;
            return true;
        }
    }

    private final WeakHashMap<VpnService.Builder, State> states = new WeakHashMap<>();

    private State stateOf(VpnService.Builder b) {
        synchronized (states) {
            State s = states.get(b);
            if (s == null) {
                s = new State();
                states.put(b, s);
            }
            return s;
        }
    }

    // ---------------------------------------------------------------- 入口

    @Override
    public void initZygote(StartupParam startupParam) {
        modulePath = startupParam.modulePath;
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.isFirstApplication) return; // 每个进程只挂一次

        selfPackage = lpparam.packageName;

        hookAllowedApplication();
        hookDisallowedApplication();
        hookLocalAddresses();
        hookEstablish();
    }

    // ---------------------------------------------------------------- hooks

    /** 名单永远为空 = 全局。 */
    private void hookAllowedApplication() {
        try {
            XposedHelpers.findAndHookMethod(VpnService.Builder.class, "addAllowedApplication",
                    String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(param.thisObject);
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook addAllowedApplication 失败: " + t);
        }
    }

    /** 吞掉别人的排除，只放行对自己的排除。 */
    private void hookDisallowedApplication() {
        try {
            XposedHelpers.findAndHookMethod(VpnService.Builder.class, "addDisallowedApplication",
                    String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String pkg = (String) param.args[0];
                            if (pkg != null && pkg.equals(selfPackage)) return; // 放行
                            param.setResult(param.thisObject);
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook addDisallowedApplication 失败: " + t);
        }
    }

    /** 记录 TUN 地址和 DNS（两个重载都会被 hook）。 */
    private void hookLocalAddresses() {
        XC_MethodHook record = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                InetAddress a = toAddress(param.args[0]);
                if (a != null) stateOf((VpnService.Builder) param.thisObject).add(a);
            }
        };
        try {
            XposedBridge.hookAllMethods(VpnService.Builder.class, "addAddress", record);
            XposedBridge.hookAllMethods(VpnService.Builder.class, "addDnsServer", record);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook addAddress/addDnsServer 失败: " + t);
        }
    }

    private void hookEstablish() {
        try {
            XposedHelpers.findAndHookMethod(VpnService.Builder.class, "establish",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            VpnService.Builder builder = (VpnService.Builder) param.thisObject;
                            State st = stateOf(builder);
                            if (!st.markDone()) return; // 同一个 Builder 只处理一次

                            String me = selfPackage;
                            if (me != null) {
                                try {
                                    builder.addDisallowedApplication(me);
                                } catch (Throwable t) {
                                    XposedBridge.log(TAG + "自排除失败: " + t);
                                }
                            }
                            excludeRoutes(builder, st);
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook establish 失败: " + t);
        }
    }

    // ---------------------------------------------------------------- 路由

    @SuppressLint("NewApi")
    private void excludeRoutes(VpnService.Builder builder, State st) {
        if (Build.VERSION.SDK_INT < 33) {
            XposedBridge.log(TAG + "系统低于 Android 13，跳过 excludeRoute");
            return;
        }

        int ok = 0, skipped = 0, failed = 0;
        for (Route r : routes()) {
            if (st.overlaps(r)) { // 包含 TUN / DNS 地址，排除会导致自己不通
                skipped++;
                continue;
            }
            try {
                builder.excludeRoute(new IpPrefix(r.addr, r.len));
                ok++;
            } catch (Throwable e) {
                if (failed++ == 0) XposedBridge.log(TAG + "排除路由失败(仅记录首个): " + r.addr.getHostAddress() + "/" + r.len + " / " + e);
            }
        }
        XposedBridge.log(TAG + "排除路由完成，成功: " + ok + "，跳过(与TUN/DNS冲突): " + skipped + "，失败: " + failed);
    }

    private synchronized List<Route> routes() {
        if (routes != null) return routes;

        List<String> lines = new ArrayList<>(Arrays.asList(PRIVATE_ROUTES));
        List<String> fromAsset = readAssetLines();
        if (fromAsset != null && !fromAsset.isEmpty()) {
            lines.addAll(fromAsset);
            XposedBridge.log(TAG + "从 " + ASSET_ROUTES + " 加载 " + fromAsset.size() + " 条");
        } else {
            lines.addAll(Arrays.asList(FALLBACK_PRECISE));
            for (int o : FALLBACK_SLASH8) lines.add(o + ".0.0.0/8");
            XposedBridge.log(TAG + "未找到 " + ASSET_ROUTES + "，使用内置粗粒度列表");
        }

        List<Route> out = new ArrayList<>(lines.size());
        for (String s : lines) {
            Route r = parse(s);
            if (r != null) out.add(r);
        }
        routes = out;
        return out;
    }

    /** 从模块 APK 里读 assets，不依赖目标进程的文件权限。 */
    private List<String> readAssetLines() {
        String path = modulePath;
        if (path == null) return null;
        try (ZipFile zf = new ZipFile(path)) {
            ZipEntry e = zf.getEntry(ASSET_ROUTES);
            if (e == null) return null;
            List<String> out = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(zf.getInputStream(e), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) out.add(line);
                }
            }
            return out;
        } catch (Throwable t) {
            XposedBridge.log(TAG + "读取 " + ASSET_ROUTES + " 失败: " + t);
            return null;
        }
    }

    private static Route parse(String cidr) {
        try {
            int slash = cidr.indexOf('/');
            if (slash <= 0) return null;
            InetAddress a = toAddress(cidr.substring(0, slash));
            if (a == null) return null;
            int len = Integer.parseInt(cidr.substring(slash + 1));
            if (len < 0 || len > a.getAddress().length * 8) return null;
            return new Route(a, len);
        } catch (Throwable t) {
            return null;
        }
    }

    /** 只接受数字地址，避免 getByName 触发 DNS 解析。 */
    private static InetAddress toAddress(Object o) {
        try {
            if (o instanceof InetAddress) return (InetAddress) o;
            if (o instanceof String && ((String) o).matches("[0-9a-fA-F:.]+")) {
                return InetAddress.getByName((String) o);
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
