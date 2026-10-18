package com.zqstudio.easyxposed;

import android.app.Application;
import android.app.AndroidAppHelper;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import java.util.List;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "[ForceGlobal] ";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {

        XposedBridge.log(TAG + "加载包名: " + lpparam.packageName);

        // -----------------------------------------------------------
        // 1. 拦截黑名单，防止 VPN App 排除应用
        // -----------------------------------------------------------
        try {
            XposedHelpers.findAndHookMethod(
                    "android.net.VpnService$Builder",
                    lpparam.classLoader,
                    "addDisallowedApplication",
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            String pkg = String.valueOf(param.args[0]);

                            XposedBridge.log(TAG + "拦截黑名单: " + pkg);

                            // 直接返回 Builder 对象，跳过原方法
                            param.setResult(param.thisObject);
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook addDisallowedApplication 失败: " + t.getMessage());
        }

        // -----------------------------------------------------------
        // 2. Hook establish，在 VPN 建立前修改规则
        // -----------------------------------------------------------
        try {
            XposedHelpers.findAndHookMethod(
                    "android.net.VpnService$Builder",
                    lpparam.classLoader,
                    "establish",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Application app = AndroidAppHelper.currentApplication();

                            if (app == null) {
                                XposedBridge.log(TAG + "currentApplication 为空，跳过");
                                return;
                            }

                            String myPkg = app.getPackageName();
                            PackageManager pm = app.getPackageManager();
                            Object builder = param.thisObject;

                            XposedBridge.log(TAG + "正在处理 VPN App: " + myPkg);

                            // 2.1 强制所有 App 加入 VPN 白名单
                            addAllAppsToVpn(builder, pm, myPkg);

                            // 2.2 安卓 13+ 排除国内 IP 路由，实现国内直连
                            excludeChinaRoutes(builder);
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Hook establish 失败: " + t.getMessage());
        }
    }

    /**
     * 把所有已安装 App 加入 VPN allowedApplication 白名单
     */
    private void addAllAppsToVpn(Object builder, PackageManager pm, String myPkg) {
        try {
            List<PackageInfo> packages = pm.getInstalledPackages(0);

            int count = 0;

            for (PackageInfo info : packages) {
                if (info == null || info.packageName == null) {
                    continue;
                }

                String pkg = info.packageName;

                // 排除 VPN 自身，避免 VPN App 自己走自己的 VPN 导致异常
                if (pkg.equals(myPkg)) {
                    continue;
                }

                try {
                    XposedHelpers.callMethod(
                            builder,
                            "addAllowedApplication",
                            pkg
                    );

                    count++;
                } catch (Throwable e) {
                    XposedBridge.log(TAG + "添加白名单失败: " + pkg + " / " + e.getMessage());
                }
            }

            XposedBridge.log(TAG + "全局白名单注入完成，共添加: " + count);

        } catch (Throwable e) {
            XposedBridge.log(TAG + "注入 App 白名单失败: " + e.getMessage());
        }
    }

    /**
     * 排除国内 IP / 局域网 IP，不走 VPN
     *
     * Android 13 / API 33 以上支持 VpnService.Builder.excludeRoute(IpPrefix)
     * 安卓 16 可以使用。
     */
    private void excludeChinaRoutes(Object builder) {
        if (Build.VERSION.SDK_INT < 33) {
            XposedBridge.log(TAG + "当前系统低于 Android 13，不支持 excludeRoute，跳过国内直连");
            return;
        }

        String[] routes = new String[] {
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

        int success = 0;
        int failed = 0;

        for (String cidr : routes) {
            try {
                Class<?> ipPrefixClass = Class.forName("android.net.IpPrefix");
                Object ipPrefix = XposedHelpers.newInstance(ipPrefixClass, cidr);

                XposedHelpers.callMethod(builder, "excludeRoute", ipPrefix);

                success++;
                XposedBridge.log(TAG + "国内直连路由成功: " + cidr);
            } catch (Throwable e) {
                failed++;
                XposedBridge.log(TAG + "国内直连路由失败: " + cidr + " / " + e.getMessage());
            }
        }

        XposedBridge.log(TAG + "国内直连规则完成，成功: " + success + "，失败: " + failed);
    }
}
