package com.zqstudio.easyxposed;

import android.app.Application;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.Method;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

public class NodeExporter {

    private static final String TAG = "[NodeExport] ";
    private static final String V2RAYNG_PKG = "com.v2ray.ang";
    private static final String FILE_NAME = "v2rayng_node.txt";

    // 不同版本类所在的包不同，依次尝试
    private static final String[] ANG_MANAGER = {
            "com.v2ray.ang.handler.AngConfigManager",
            "com.v2ray.ang.util.AngConfigManager"
    };
    private static final String[] MMKV_MANAGER = {
            "com.v2ray.ang.handler.MmkvManager",
            "com.v2ray.ang.util.MmkvManager"
    };

    private static String lastLink = "";

    public static boolean isTarget(String pkg) {
        return V2RAYNG_PKG.equals(pkg);
    }

    /** 在 VPN 建立时调用：取出当前选中节点，导出为分享链接 */
    public static void export(Application app, ClassLoader cl) {
        try {
            String guid = getSelectedGuid(cl);
            if (guid == null || guid.isEmpty()) {
                XposedBridge.log(TAG + "未取到当前节点 ID");
                return;
            }

            String link = getShareLink(cl, guid);
            if (link == null || link.isEmpty()) {
                XposedBridge.log(TAG + "未能生成分享链接");
                return;
            }

            // 同一个节点重复连接时不重复写
            if (link.equals(lastLink)) return;
            lastLink = link;

            save(app, link);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "导出失败: " + t);
        }
    }

    private static String getSelectedGuid(ClassLoader cl) {
        Object mmkv = getKotlinObject(cl, MMKV_MANAGER);
        if (mmkv == null) {
            XposedBridge.log(TAG + "找不到 MmkvManager");
            return null;
        }
        try {
            Object r = XposedHelpers.callMethod(mmkv, "getSelectServer");
            return r == null ? null : r.toString();
        } catch (Throwable t) {
            logMethods(mmkv.getClass(), "select");
            return null;
        }
    }

    private static String getShareLink(ClassLoader cl, String guid) {
        Object mgr = getKotlinObject(cl, ANG_MANAGER);
        if (mgr == null) {
            XposedBridge.log(TAG + "找不到 AngConfigManager");
            return null;
        }
        try {
            Object r = XposedHelpers.callMethod(mgr, "shareConfig", guid);
            return r == null ? null : r.toString().trim();
        } catch (Throwable t) {
            XposedBridge.log(TAG + "调用 shareConfig 失败: " + t);
            logMethods(mgr.getClass(), "share");
            return null;
        }
    }

    /** 取 Kotlin object 单例（INSTANCE 字段） */
    private static Object getKotlinObject(ClassLoader cl, String[] candidates) {
        for (String name : candidates) {
            Class<?> c = XposedHelpers.findClassIfExists(name, cl);
            if (c == null) continue;
            try {
                return XposedHelpers.getStaticObjectField(c, "INSTANCE");
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    /** 方法名对不上时，把相近的方法名打到日志里，方便排查 */
    private static void logMethods(Class<?> c, String keyword) {
        for (Method m : c.getDeclaredMethods()) {
            if (m.getName().toLowerCase().contains(keyword)) {
                XposedBridge.log(TAG + "候选方法: " + c.getSimpleName() + "." + m.getName());
            }
        }
    }

    private static void save(Application app, String content) {
        byte[] data = (content + "\n").getBytes(StandardCharsets.UTF_8);

        // 优先写到公共「下载」目录
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                saveToDownloads(app, data);
                XposedBridge.log(TAG + "已写入 Download/" + FILE_NAME);
                return;
            } catch (Throwable t) {
                XposedBridge.log(TAG + "写入下载目录失败，改用应用目录: " + t);
            }
        }

        // 备用：v2rayNG 自己的外部目录
        try {
            File dir = app.getExternalFilesDir(null);
            if (dir == null) dir = app.getFilesDir();
            File f = new File(dir, FILE_NAME);
            try (OutputStream os = new FileOutputStream(f, false)) {
                os.write(data);
            }
            XposedBridge.log(TAG + "已写入 " + f.getAbsolutePath());
        } catch (Throwable t) {
            XposedBridge.log(TAG + "写文件失败: " + t);
        }
    }

    private static void saveToDownloads(Application app, byte[] data) throws Exception {
        ContentResolver cr = app.getContentResolver();
        Uri collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
        Uri target = null;

        // 已有同名文件就覆盖，避免生成 xxx(1).txt
        try (Cursor c = cr.query(collection,
                new String[]{MediaStore.Downloads._ID},
                MediaStore.Downloads.DISPLAY_NAME + "=?",
                new String[]{FILE_NAME}, null)) {
            if (c != null && c.moveToFirst()) {
                target = ContentUris.withAppendedId(collection, c.getLong(0));
            }
        }

        if (target == null) {
            ContentValues v = new ContentValues();
            v.put(MediaStore.Downloads.DISPLAY_NAME, FILE_NAME);
            v.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
            v.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
            target = cr.insert(collection, v);
        }
        if (target == null) throw new IllegalStateException("insert 返回空");

        try (OutputStream os = cr.openOutputStream(target, "wt")) {
            if (os == null) throw new IllegalStateException("无法打开输出流");
            os.write(data);
        }
    }
}
