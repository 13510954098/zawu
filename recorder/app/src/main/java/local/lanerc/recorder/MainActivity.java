package local.lanerc.recorder;

import android.app.*;
import android.content.*;
import android.media.projection.MediaProjectionManager;
import android.net.Uri;
import android.os.*;
import android.provider.Settings;
import android.widget.*;
import java.io.*;

public class MainActivity extends Activity {
    EditText notes; TextView state; boolean requesting;
    void message(String s) { new AlertDialog.Builder(this).setMessage(s).setPositiveButton("知道了",null).show(); }
    protected void onCreate(Bundle b) { super.onCreate(b); render(); }
    protected void onResume() { super.onResume(); if(state!=null) update(); }
    protected void onNewIntent(Intent i) { super.onNewIntent(i); update(); }
    void update() {
        String status=Session.active?(Session.paused?"已暂停":"记录中"):(Session.dir(this).exists()?"有待导出的本地记录":"尚无记录");
        state.setText(status+"\n无障碍已连接："+ObserverService.connected+"\n悬浮窗："+Settings.canDrawOverlays(this)+"\n通知可用："+getSystemService(NotificationManager.class).areNotificationsEnabled());
    }
    void button(LinearLayout layout,String text,Runnable r) { Button b=new Button(this); b.setText(text); b.setOnClickListener(v->r.run()); layout.addView(b); }
    void render() {
        ScrollView scroll=new ScrollView(this); LinearLayout root=new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(28,28,28,40); scroll.addView(root); setContentView(scroll);
        TextView title=new TextView(this); title.setText("Lanerc 本地测试记录器"); title.setTextSize(24); root.addView(title);
        TextView info=new TextView(this); info.setText("无 Google 服务 · 无 root · 无 ADB · 不联网\n仅用于本人授权测试。不会自动点击广告或伪造奖励。\n录像可能包含账号等敏感画面，不做可靠的自动脱敏。请先隐藏敏感内容；切换其他应用前可暂停。节点文本一律不保存。\n操作顺序：开始 → 可选授权 → 自行操作 Lanerc → 结束 → 填写备注 → 导出。\n若拒绝录屏/无障碍，对应内容不可用。拒绝所有授权仍可记录手动开始/结束时间与备注。\n系统受保护窗口可能黑屏，无法可靠自动识别；Flutter 节点可能不完整。"); root.addView(info);
        state=new TextView(this); root.addView(state);
        button(root,"可选：授权无障碍（仅被动观察 Lanerc）",()-> new AlertDialog.Builder(this).setMessage("只记录目标包的事件时间和节点结构，不读取文字、密码或描述，不执行点击。Flutter/广告可能无法读取。请在系统设置中启用本记录器；可随时关闭。Android 13+ 侧载应用可能需在应用信息右上角允许受限设置。") .setPositiveButton("打开系统设置",(d,w)->startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))).setNegativeButton("不授权",null).show());
        button(root,"可选：授权悬浮控制按钮",()-> { try { startActivity(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,Uri.parse("package:"+getPackageName()))); } catch(Exception e) { message("无法打开设置，可使用通知或返回应用控制。"); } });
        if(Build.VERSION.SDK_INT>=33) button(root,"可选：允许控制通知",()->requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"},20));
        button(root,"开始记录",()-> {
            if(Session.active) { message("已在记录中"); return; }
            if(Session.dir(this).exists()) { message("请先导出或删除上次记录，不会自动覆盖。"); return; }
            new AlertDialog.Builder(this).setTitle("确认本地记录与隐私风险").setMessage("屏幕录像不录声音，但会包含屏幕上的敏感内容，无法保证脱敏。请避免输入密码或显示账号；随时可通过通知/悬浮按钮/返回本应用暂停。未授权的项目不会被记录。\n\n选择是否申请本次屏幕录制授权：")
              .setPositiveButton("同意并申请录屏",(d,w)->begin(true)).setNeutralButton("同意，仅时间线（不录屏）",(d,w)->begin(false)).setNegativeButton("取消",null).show();
        });
        button(root,"暂停 / 继续记录",()-> { if(Session.active) startService(new Intent(this,CaptureService.class).setAction(CaptureService.PAUSE)); else message("当前未记录"); update(); });
        button(root,"结束并导出（先停止，下面填备注）",()-> { if(Session.active) { startService(new Intent(this,CaptureService.class).setAction(CaptureService.STOP)); state.postDelayed(this::update,500); } else message("已停止，请填写备注并点击保存 ZIP。"); });
        notes=new EditText(this); notes.setHint("用户备注（请勿填写密码/令牌/个人信息）\n播放成功了吗？\n次数前后变化？\n重启后是否保留？"); notes.setMinLines(4); root.addView(notes);
        button(root,"导出 ZIP → 系统保存对话框",()-> {
            if(Session.active || requesting) { message("请先结束记录"); return; }
            if(!Session.file(this,"metadata.json").exists()) { message("没有可导出的记录"); return; }
            new AlertDialog.Builder(this).setTitle("分享前检查隐私").setMessage("录像和备注可能包含敏感信息，无法保证自动脱敏。ZIP 仅保存到您选择的位置；应用不上传。请在分享前检查 report、事件和录像。")
              .setPositiveButton("选择保存位置",(d,w)-> { Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"lanerc-recording-"+System.currentTimeMillis()+".zip"); try { startActivityForResult(i,12); } catch(Exception e) { message("系统文件选择器不可用："+e.getClass().getSimpleName()); } }).setNegativeButton("取消",null).show();
        });
        button(root,"一键删除本次本地记录",()-> {
            if(Session.active || requesting) { message("请先结束记录，再删除"); return; }
            new AlertDialog.Builder(this).setMessage("永久删除应用内本次记录和临时 ZIP？已保存到外部位置的副本需您自行删除。") .setPositiveButton("删除",(d,w)-> { Session.delete(this); notes.setText(""); update(); }).setNegativeButton("取消",null).show();
        });
        update();
    }
    void begin(boolean screen) {
        if(Session.active || requesting) return;
        try {
            Session.start(this);
            if(!getSystemService(NotificationManager.class).areNotificationsEnabled() && !Settings.canDrawOverlays(this)) message("通知和悬浮窗均不可用，请返回本记录器暂停/结束。Android 11 默认显示前台通知；请勿在系统中屏蔽控制通知。");
            if(screen) { requesting=true; startActivityForResult(getSystemService(MediaProjectionManager.class).createScreenCaptureIntent(),11); }
            else launchRecorder(0,null);
        } catch(Exception e) { requesting=false; Session.active=false; Session.event(this,"start_error",e.getClass().getSimpleName()); message("无法开始："+e.getMessage()+"。已有内容保留，可导出或删除。"); }
    }
    void launchRecorder(int code,Intent data) {
        requesting=false;
        Intent s=new Intent(this,CaptureService.class).putExtra("code",code); if(data!=null) s.putExtra("data",data);
        try { startForegroundService(s); }
        catch(Exception e) { Session.event(this,"foreground_service_failed",e.getClass().getSimpleName()); Session.active=false; message("前台服务启动失败，记录已停止："+e.getClass().getSimpleName()); }
        update();
    }
    protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request==11) { if(result!=RESULT_OK) Session.event(this,"screen_permission_denied","用户拒绝录屏；只保留可用时间线"); launchRecorder(result,data); }
        if(request==12 && result==RESULT_OK && data!=null && data.getData()!=null) {
            final Uri uri=data.getData(); final String text=notes.getText().toString();
            new Thread(()-> {
                try {
                    if(!Session.meta(this).has("stoppedAt")) { Session.status(this,"termination","未收到正常结束标记：可能系统终止进程；视频可能损坏"); }
                    File zip=Session.zip(this,text);
                    try(InputStream in=new FileInputStream(zip); OutputStream out=getContentResolver().openOutputStream(uri,"wt")) {
                        if(out==null) throw new IOException("目标不可写"); byte[] b=new byte[32768]; int n; while((n=in.read(b))!=-1) out.write(b,0,n);
                    }
                    zip.delete(); runOnUiThread(()->message("ZIP 已保存。请自行检查内容；确认无敏感信息后，可把 ZIP 发回本对话分析。原始本地记录仍保留，可一键删除。"));
                } catch(Exception e) { Session.event(this,"export_error",e.getClass().getSimpleName()); runOnUiThread(()->message("导出失败："+e.getClass().getSimpleName()+"。本地记录已保留，可重试；目标位置可能有不完整 ZIP，请删除该副本。")); }
            },"zip-export").start();
        }
    }
}
