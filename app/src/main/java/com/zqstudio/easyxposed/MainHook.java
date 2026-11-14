package com.zqstudio.easyxposed;

import android.annotation.SuppressLint;
import android.net.IpPrefix;
import android.net.VpnService;
import android.os.Build;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
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
 * 3. 路由表只从模块 APK 的 assets/cn_routes.txt 读取（一行一个 CIDR，支持 IPv4/IPv6）。
 *    读取不到 / 文件为空 -> 只排除局域网地址，其余全部走 VPN。
 *    局域网 / 私有地址无论如何都直连。
 * 4. 加载后自动合并重叠、相邻的网段，减少 excludeRoute 的条数。
 * 5. 记录 VPN 自己的 TUN 地址 / DNS，凡是包含这些地址的排除段一律跳过，避免 DNS 或回环失效。
 *
 * 需要 compileSdk >= 33。LSPosed 作用域只勾选目标 VPN App。
 */
public class MainHook implements IXposedHookZygoteInit, IXposedHookLoadPackage {

    private static final String TAG = "[ForceGlobal] ";
    private static final String ASSET_ROUTES = "assets/cn_routes.txt";

    /** 局域网 / 私有地址（IPv4 + IPv6），始终排除（直连） */
    private static final String[] PRIVATE_ROUTES = {
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16",
            "fc00::/7", "fe80::/10"
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

        List<Route> list = routes();
        if (list.isEmpty()) {
            XposedBridge.log(TAG + "没有可用的路由表，不排除任何路由，全部走 VPN");
            return;
        }

        int ok = 0, skipped = 0, failed = 0;
        for (Route r : list) {
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

        // 局域网地址始终排除（直连），不管有没有 cn_routes.txt
        List<String> lines = new ArrayList<>(Arrays.asList(PRIVATE_ROUTES));

        List<String> fromAsset = readAssetLines();
        boolean hasAsset = fromAsset != null && !fromAsset.isEmpty();
        if (hasAsset) {
            lines.addAll(fromAsset);
        } else {
            XposedBridge.log(TAG + "未找到或读不到 " + ASSET_ROUTES + "，仅排除局域网地址，其余全部走 VPN");
        }

        List<Route> parsed = new ArrayList<>(lines.size());
        for (String s : lines) {
            Route r = parse(s);
            if (r != null) parsed.add(r);
        }

        List<Route> merged = merge(parsed);
        if (hasAsset) {
            XposedBridge.log(TAG + "从 " + ASSET_ROUTES + " 加载 " + fromAsset.size()
                    + " 条，加上局域网后合并为 " + merged.size() + " 条");
        }
        routes = merged;
        return routes;
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
            int len = Integer.parseInt(cidr.substring(slash + 1).trim());
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

    // ---------------------------------------------------------------- 合并网段

    /** 合并重叠 / 相邻的网段，IPv4 与 IPv6 分开处理。 */
    private static List<Route> merge(List<Route> in) {
        List<Route> v4 = new ArrayList<>();
        List<Route> v6 = new ArrayList<>();
        for (Route r : in) {
            if (r.addr.getAddress().length == 4) v4.add(r);
            else v6.add(r);
        }
        List<Route> out = new ArrayList<>();
        out.addAll(mergeFamily(v4, 4));
        out.addAll(mergeFamily(v6, 16));
        return out;
    }

    private static List<Route> mergeFamily(List<Route> list, int bytes) {
        List<Route> out = new ArrayList<>();
        if (list.isEmpty()) return out;
        final int bits = bytes * 8;

        // 每个网段 -> [起点, 终点]
        List<BigInteger[]> ranges = new ArrayList<>(list.size());
        for (Route r : list) {
            int host = bits - r.len;
            BigInteger start = new BigInteger(1, r.addr.getAddress()).shiftRight(host).shiftLeft(host);
            BigInteger end = start.add(BigInteger.ONE.shiftLeft(host)).subtract(BigInteger.ONE);
            ranges.add(new BigInteger[]{start, end});
        }
        Collections.sort(ranges, new Comparator<BigInteger[]>() {
            @Override
            public int compare(BigInteger[] a, BigInteger[] b) {
                return a[0].compareTo(b[0]);
            }
        });

        // 合并重叠 / 相邻区间
        List<BigInteger[]> merged = new ArrayList<>();
        BigInteger[] cur = ranges.get(0);
        for (int i = 1; i < ranges.size(); i++) {
            BigInteger[] nx = ranges.get(i);
            if (nx[0].compareTo(cur[1].add(BigInteger.ONE)) <= 0) {
                if (nx[1].compareTo(cur[1]) > 0) cur = new BigInteger[]{cur[0], nx[1]};
            } else {
                merged.add(cur);
                cur = nx;
            }
        }
        merged.add(cur);

        // 区间 -> 尽量少的 CIDR
        for (BigInteger[] rg : merged) {
            BigInteger start = rg[0];
            BigInteger end = rg[1];
            while (start.compareTo(end) <= 0) {
                int align = start.signum() == 0 ? bits : start.getLowestSetBit();
                int fit = end.subtract(start).add(BigInteger.ONE).bitLength() - 1;
                int k = Math.min(align, fit);
                try {
                    out.add(new Route(InetAddress.getByAddress(toBytes(start, bytes)), bits - k));
                } catch (Throwable ignored) {
                }
                start = start.add(BigInteger.ONE.shiftLeft(k));
            }
        }
        return out;
    }

    private static byte[] toBytes(BigInteger v, int bytes) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[bytes];
        int copy = Math.min(raw.length, bytes);
        System.arraycopy(raw, raw.length - copy, out, bytes - copy, copy);
        return out;
    }
}
