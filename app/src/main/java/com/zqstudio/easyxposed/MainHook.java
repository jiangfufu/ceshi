package com.zqstudio.easyxposed;

import android.annotation.SuppressLint;
import android.app.AndroidAppHelper;
import android.app.Application;
import android.net.IpPrefix;
import android.net.VpnService;
import android.os.Build;

import java.net.InetAddress;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 思路：
 * 1. addAllowedApplication / addDisallowedApplication 全部变成空操作 -> 名单为空 = 全局 VPN，
 *    不再枚举已安装应用（避开包可见性限制，也覆盖之后新装的应用）。
 * 2. 唯一例外：放行 VPN App 对自己的排除，并在 establish 里补一次，避免自己的流量回环进 TUN。
 * 3. establish 前（API 33+）用 excludeRoute 排除局域网 / 国内网段。
 *
 * 需要 compileSdk >= 33。LSPosed 作用域建议只勾选目标 VPN App。
 */
public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "[ForceGlobal] ";

    // 原表原样保留。注意：很多整段 /8 并非中国专属，建议换成按 APNIC 数据生成的精确列表。
    // 另外 10.0.0.0/8、172.16.0.0/12 若与 VPN 自己的虚拟网卡/DNS 地址重叠，会导致 DNS 失效。
    private static final String[] ROUTES = new String[] {
            // 局域网 / 私有地址
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",

            // 国内常见 IPv4 大段，网页分流测试用
            "1.0.1.0/24",
            "1.0.2.0/23",
            "1.0.8.0/21",
            "1.0.32.0/19",

            "14.16.0.0/12",
            "27.8.0.0/13",
            "27.16.0.0/12",

            "36.0.0.0/8",
            "39.0.0.0/8",
            "42.0.0.0/8",

            "49.4.0.0/14",
            "49.64.0.0/11",

            "58.0.0.0/8",
            "59.0.0.0/8",
            "60.0.0.0/8",
            "61.0.0.0/8",

            "101.0.0.0/8",
            "103.0.0.0/8",
            "106.0.0.0/8",

            "110.0.0.0/8",
            "111.0.0.0/8",
            "112.0.0.0/8",
            "113.0.0.0/8",
            "114.0.0.0/8",
            "115.0.0.0/8",
            "116.0.0.0/8",
            "117.0.0.0/8",
            "118.0.0.0/8",
            "119.0.0.0/8",

            "120.0.0.0/8",
            "121.0.0.0/8",
            "122.0.0.0/8",
            "123.0.0.0/8",
            "124.0.0.0/8",
            "125.0.0.0/8",

            "139.0.0.0/8",
            "140.0.0.0/8",
            "144.0.0.0/8",
            "150.0.0.0/8",
            "153.0.0.0/8",
            "157.0.0.0/8",
            "163.0.0.0/8",
            "171.0.0.0/8",
            "175.0.0.0/8",

            "180.0.0.0/8",
            "182.0.0.0/8",
            "183.0.0.0/8",

            "202.0.0.0/8",
            "203.0.0.0/8",
            "210.0.0.0/8",
            "211.0.0.0/8",

            "218.0.0.0/8",
            "219.0.0.0/8",
            "220.0.0.0/8",
            "221.0.0.0/8",
            "222.0.0.0/8",
            "223.0.0.0/8"
    };

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        // 每个进程只挂一次
        if (!lpparam.isFirstApplication) {
            return;
        }

        hookAllowedApplication();
        hookDisallowedApplication();
        hookEstablish();
    }

    /** 名单永远为空 = 全局。 */
    private void hookAllowedApplication() {
        try {
            XposedHelpers.findAndHookMethod(
                    VpnService.Builder.class,
                    "addAllowedApplication",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(param.thisObject);
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook addAllowedApplication 失败: " + t);
        }
    }

    /** 吞掉别人的排除，只放行对自己的排除（防回环）。 */
    private void hookDisallowedApplication() {
        try {
            XposedHelpers.findAndHookMethod(
                    VpnService.Builder.class,
                    "addDisallowedApplication",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String pkg = (String) param.args[0];
                            String me = currentPackage();
                            if (pkg != null && pkg.equals(me)) {
                                return; // 放行，执行原方法
                            }
                            param.setResult(param.thisObject);
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook addDisallowedApplication 失败: " + t);
        }
    }

    private void hookEstablish() {
        try {
            XposedHelpers.findAndHookMethod(
                    VpnService.Builder.class,
                    "establish",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            VpnService.Builder builder = (VpnService.Builder) param.thisObject;

                            // 确保 VPN App 自己不进自己的 VPN（走上面放行的分支）
                            String me = currentPackage();
                            if (me != null) {
                                try {
                                    builder.addDisallowedApplication(me);
                                } catch (Throwable t) {
                                    XposedBridge.log(TAG + "自排除失败: " + t);
                                }
                            }

                            excludeRoutes(builder);
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook establish 失败: " + t);
        }
    }

    /** Android 13 / API 33+ 才有 excludeRoute。 */
    @SuppressLint("NewApi")
    private void excludeRoutes(VpnService.Builder builder) {
        if (Build.VERSION.SDK_INT < 33) {
            XposedBridge.log(TAG + "系统低于 Android 13，跳过 excludeRoute");
            return;
        }

        int ok = 0;
        int failed = 0;

        for (String cidr : ROUTES) {
            try {
                int slash = cidr.indexOf('/');
                InetAddress addr = InetAddress.getByName(cidr.substring(0, slash));
                int prefixLen = Integer.parseInt(cidr.substring(slash + 1));
                builder.excludeRoute(new IpPrefix(addr, prefixLen));
                ok++;
            } catch (Throwable e) {
                failed++;
                XposedBridge.log(TAG + "排除路由失败: " + cidr + " / " + e);
            }
        }

        XposedBridge.log(TAG + "排除路由完成，成功: " + ok + "，失败: " + failed);
    }

    private static String currentPackage() {
        Application app = AndroidAppHelper.currentApplication();
        return app != null ? app.getPackageName() : null;
    }
}
