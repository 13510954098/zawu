package local.lanerc.recorder;

import android.content.*;
import android.os.Build;
import android.provider.Settings;
import android.util.DisplayMetrics;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.*;

final class Session {
    static final String TARGET = "com.clggjv.xcjfmd.ffo";
    static volatile boolean active, paused, exporting;
    static File dir(Context c) { return new File(c.getFilesDir(), "session"); }
    static File file(Context c, String name) { return new File(dir(c), name); }
    static synchronized void start(Context c) throws Exception {
        if (dir(c).exists()) throw new IOException("已有记录，请先导出或删除");
        if (!dir(c).mkdirs()) throw new IOException("无法创建本地目录");
        active = true; paused = false;
        JSONObject info = new JSONObject();
        info.put("startedAt", stamp()); info.put("android", Build.VERSION.RELEASE);
        info.put("sdk", Build.VERSION.SDK_INT); info.put("targetPackage", TARGET);
        DisplayMetrics dm = c.getResources().getDisplayMetrics();
        info.put("screen", dm.widthPixels + "x" + dm.heightPixels);
        try { info.put("targetVersion", c.getPackageManager().getPackageInfo(TARGET, 0).versionName); }
        catch (Exception e) { info.put("targetVersion", "未安装或不可查询"); }
        info.put("recorderVersion", c.getPackageManager().getPackageInfo(c.getPackageName(),0).versionName);
        info.put("overlayAtStart", Settings.canDrawOverlays(c));
        info.put("accessibilityConnectedAtStart", ObserverService.connected);
        info.put("notificationAtStart", c.getSystemService(android.app.NotificationManager.class).areNotificationsEnabled());
        info.put("screenStatus", "未授权 / 未启动");
        save(c, info); event(c, "session_start", "用户明确开始记录；只记录本次会话");
    }
    static String stamp() { return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US).format(new Date()); }
    static synchronized JSONObject meta(Context c) throws Exception {
        return new JSONObject(new String(java.nio.file.Files.readAllBytes(file(c,"metadata.json").toPath()), StandardCharsets.UTF_8));
    }
    static void save(Context c, JSONObject o) throws Exception {
        try (FileOutputStream out = new FileOutputStream(file(c,"metadata.json"))) { out.write(o.toString(2).getBytes(StandardCharsets.UTF_8)); }
    }
    static synchronized void status(Context c, String key, Object value) {
        try { JSONObject o=meta(c); o.put(key,value); save(c,o); } catch(Exception e) { event(c,"metadata_error", e.getClass().getSimpleName()); }
    }
    static synchronized void event(Context c, String type, String detail) {
        if (!dir(c).exists()) return;
        try {
            JSONObject o=new JSONObject(); o.put("time",stamp()); o.put("elapsedMs",android.os.SystemClock.elapsedRealtime()); o.put("type",type); o.put("detail",detail);
            File f=file(c,"events.jsonl");
            if(f.length()>16*1024*1024) { statusNoEvent(c); return; }
            try(FileOutputStream out=new FileOutputStream(f,true)) { out.write((o+"\n").getBytes(StandardCharsets.UTF_8)); }
        } catch(Exception e) { statusNoEvent(c); }
    }
    static void statusNoEvent(Context c) { try(FileOutputStream out=new FileOutputStream(file(c,"recording-error.txt"))) { out.write("事件写入失败或超过16MiB上限；时间线可能不完整".getBytes(StandardCharsets.UTF_8)); } catch(Exception ignored) {} }
    static String redactNotes(String s) {
        // Conservative best-effort filtering, never a claim that images or arbitrary prose are safe.
        return s.replaceAll("(?i)(password|passwd|token|secret|authorization|cookie|密码|口令|令牌|账号|账户)\\s*[:：=]\\s*[^\\s,，;；]+", "$1=[REDACTED]")
            .replaceAll("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", "[EMAIL]")
            .replaceAll("(?<![0-9])[0-9]{7,}(?![0-9])", "[NUMBER]")
            .replaceAll("[A-Za-z0-9_\\-]{24,}", "[POSSIBLE_TOKEN]");
    }
    static synchronized File zip(Context c, String notes) throws Exception {
        if(active) throw new IOException("请先结束记录");
        String report="Lanerc 本地测试记录\n\n"+meta(c).toString(2)+"\n\n用户备注（用户自行填写，未自动验证）：\n"+redactNotes(notes)+
            "\n\n已知限制与隐私说明：\n仅本地记录；无网络权限，无设备唯一标识，无音频。\n节点不含任何文本、描述、viewId；密码节点及其子树跳过，只保留结构与屏幕坐标。\nFlutter/自绘可能无完整节点；空树不代表没有界面。广告若属于其他包，故意不采集其无障碍内容。\nMediaProjection 没有可靠的第三方 FLAG_SECURE 检测接口：安全窗口可能显示黑屏，无法自动确认或区分静态黑屏，需人工查看录像。不能声称已录到受保护画面。\n录像仍可能包含账号等敏感画面，不能保证自动脱敏；请审查后再分享。\n暂停期间不记录界面事件；视频暂停不包含该时段，按 video_started/video_paused/video_resumed 对齐时间线。\n不读取私有文件、完整 logcat 或 HTTPS 明文；无广告自动点击、奖励伪造、VPN。\n系统杀进程可能导致 MP4 未完成；导出保留现有文件和错误，不保证损坏视频可播放。\n";
        try(FileOutputStream out=new FileOutputStream(file(c,"report.txt"))) { out.write(report.getBytes(StandardCharsets.UTF_8)); }
        File zip=new File(c.getCacheDir(),"lanerc-recording.zip");
        try(ZipOutputStream out=new ZipOutputStream(new FileOutputStream(zip))) {
            for(String name: new String[]{"report.txt","events.jsonl","screen.mp4","recording-error.txt"}) {
                File f=file(c,name); if(!f.exists()) continue;
                out.putNextEntry(new ZipEntry(name)); try(FileInputStream in=new FileInputStream(f)) { byte[] b=new byte[32768]; int n; while((n=in.read(b))!=-1) out.write(b,0,n); } out.closeEntry();
            }
        } catch(Exception e) { zip.delete(); event(c,"zip_error",e.getClass().getSimpleName()); throw e; }
        return zip;
    }
    static synchronized void delete(Context c) { File[] fs=dir(c).listFiles(); if(fs!=null) for(File f:fs) f.delete(); dir(c).delete(); new File(c.getCacheDir(),"lanerc-recording.zip").delete(); }
}
