package com.zqstudio.easyxposed;
import android.app.AndroidAppHelper;
import android.app.Application;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import java.util.List;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        
        // -----------------------------------------------------------
        // 1. 拦截黑名单 (防止 VPN App 排除应用)
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
                        // 拦截！直接返回 builder 对象，假装成功
                        param.setResult(param.thisObject);
                        XposedBridge.log("[ForceGlobal] 拦截黑名单: " + param.args[0]);
                    }
                }
            );
        } catch (Throwable t) {
            // 忽略异常，部分 App 可能没有这个方法
        }

        // -----------------------------------------------------------
        // 2. 注入白名单 (强制添加所有应用)
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
                        if (app == null) return;
                        
                        String myPkg = app.getPackageName();
                        PackageManager pm = app.getPackageManager();
                        Object builder = param.thisObject;

                        XposedBridge.log("[ForceGlobal] 正在处理 VPN: " + myPkg);

                        try {
                            // 获取所有已安装应用
                            List<PackageInfo> packages = pm.getInstalledPackages(0);
                            for (PackageInfo info : packages) {
                                String pkg = info.packageName;
                                // 排除 VPN 自身，防止断网
                                if (!pkg.equals(myPkg)) {
                                    XposedHelpers.callMethod(builder, "addAllowedApplication", pkg);
                                }
                            }
                            XposedBridge.log("[ForceGlobal] 全局白名单注入完成。");
                        } catch (Exception e) {
                            XposedBridge.log("[ForceGlobal] 注入失败: " + e.getMessage());
                        }
                    }
                }
            );
        } catch (Throwable t) {
            XposedBridge.log("[ForceGlobal] Hook establish 失败: " + t.getMessage());
        }
    }
}
