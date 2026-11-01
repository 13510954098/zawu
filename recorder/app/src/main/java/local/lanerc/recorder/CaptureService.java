package local.lanerc.recorder;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.graphics.PixelFormat;
import android.hardware.display.*;
import android.media.MediaRecorder;
import android.media.projection.*;
import android.os.*;
import android.provider.Settings;
import android.util.DisplayMetrics;
import android.view.*;
import android.widget.*;

public class CaptureService extends Service {
    static final String STOP="stop", PAUSE="pause";
    MediaProjection projection; MediaRecorder recorder; VirtualDisplay display;
    WindowManager wm; View overlay; boolean finishing, videoRunning;
    final Handler handler=new Handler(Looper.getMainLooper());
    final Runnable diskCheck=new Runnable() { public void run() {
        if(!Session.active) return;
        if(Session.dir(CaptureService.this).getUsableSpace()<64L*1024*1024) { Session.event(CaptureService.this,"low_storage","剩余不足64MiB，提前停止"); finish(); }
        else handler.postDelayed(this,3000);
    }};
    public IBinder onBind(Intent i) { return null; }
    public int onStartCommand(Intent i,int flags,int startId) {
        if(i==null) { stopSelf(); return START_NOT_STICKY; }
        if(STOP.equals(i.getAction())) { finish(); return START_NOT_STICKY; }
        if(PAUSE.equals(i.getAction())) { toggle(); return START_NOT_STICKY; }
        if(!Session.active || finishing) { stopSelf(); return START_NOT_STICKY; }
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel("record","本地记录控制",NotificationManager.IMPORTANCE_LOW));
        boolean screen=i.getIntExtra("code",0)==Activity.RESULT_OK;
        try {
            startForeground(1,notification(),screen?ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION:ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            if(screen) startVideo(i);
            else Session.status(this,"screenStatus","用户未授权：没有录像");
            addOverlay(); handler.postDelayed(diskCheck,3000);
            Intent launch=getPackageManager().getLaunchIntentForPackage(Session.TARGET);
            if(launch!=null) { launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); startActivity(launch); Session.event(this,"target_launch_requested","已请求启动；系统可能限制后台启动，请手动进入 Lanerc"); }
            else { Session.event(this,"target_missing","未安装或无可启动入口"); Toast.makeText(this,"未发现 Lanerc 启动入口，请确认安装后手动进入",Toast.LENGTH_LONG).show(); }
        } catch(Exception e) { Session.event(this,"service_error",e.getClass().getSimpleName()); finish(); }
        return START_NOT_STICKY;
    }
    Notification notification() {
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent end=PendingIntent.getService(this,1,new Intent(this,CaptureService.class).setAction(STOP),PendingIntent.FLAG_IMMUTABLE);
        PendingIntent pause=PendingIntent.getService(this,2,new Intent(this,CaptureService.class).setAction(PAUSE),PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this,"record").setSmallIcon(android.R.drawable.presence_video_online).setContentTitle(Session.paused?"本地记录已暂停":"本地测试记录中（无音频）")
            .setContentText("点击返回；结束后点导出，选择保存位置").setContentIntent(open).setOngoing(true)
            .addAction(0,Session.paused?"继续":"暂停",pause).addAction(0,"结束并导出",end).build();
    }
    void startVideo(Intent i) throws Exception {
        try {
            projection=getSystemService(MediaProjectionManager.class).getMediaProjection(i.getIntExtra("code",0),i.getParcelableExtra("data"));
            projection.registerCallback(new MediaProjection.Callback() { public void onStop() {
                if(!finishing) { Session.event(CaptureService.this,"projection_interrupted","系统/用户撤销录屏；安全窗口黑屏无法可靠自动检测"); Session.status(CaptureService.this,"screenStatus","录屏被系统或用户中断"); finish(); }
            }},handler);
            DisplayMetrics dm=getResources().getDisplayMetrics();
            float scale=Math.min(1f,1280f/Math.max(dm.widthPixels,dm.heightPixels));
            int w=((int)(dm.widthPixels*scale)/2)*2,h=((int)(dm.heightPixels*scale)/2)*2;
            recorder=new MediaRecorder(); recorder.setVideoSource(MediaRecorder.VideoSource.SURFACE);
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4); recorder.setOutputFile(Session.file(this,"screen.mp4").getAbsolutePath());
            recorder.setVideoEncoder(MediaRecorder.VideoEncoder.H264); recorder.setVideoSize(w,h); recorder.setVideoFrameRate(30); recorder.setVideoEncodingBitRate(4000000);
            recorder.setOnErrorListener((m,what,extra)-> { Session.event(this,"video_error","what="+what+" extra="+extra); finish(); });
            recorder.prepare();
            display=projection.createVirtualDisplay("Local test",w,h,dm.densityDpi,DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,recorder.getSurface(),null,handler);
            recorder.start(); videoRunning=true; Session.event(this,"video_started","仅画面，无麦克风；固定方向/尺寸，旋转可能留边"); Session.status(this,"screenStatus","已启动；是否含安全黑屏需人工检查");
        } catch(Exception e) { Session.event(this,"video_start_failed",e.getClass().getSimpleName()); Session.status(this,"screenStatus","启动失败："+e.getClass().getSimpleName()); release(); }
    }
    void toggle() {
        if(!Session.active) return;
        try {
            if(videoRunning) { if(Session.paused) recorder.resume(); else recorder.pause(); }
            Session.paused=!Session.paused;
            Session.event(this,Session.paused?"video_paused":"video_resumed","整个记录会话暂停状态="+Session.paused);
            getSystemService(NotificationManager.class).notify(1,notification());
        } catch(Exception e) { Session.event(this,"pause_failed",e.getClass().getSimpleName()); finish(); }
    }
    void addOverlay() {
        if(!Settings.canDrawOverlays(this)) return;
        try {
            wm=getSystemService(WindowManager.class); LinearLayout box=new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL);
            Button p=new Button(this); p.setText("暂停 / 继续"); p.setOnClickListener(v->toggle()); box.addView(p);
            Button s=new Button(this); s.setText("结束并导出"); s.setOnClickListener(v->finish()); box.addView(s);
            WindowManager.LayoutParams lp=new WindowManager.LayoutParams(-2,-2,WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,PixelFormat.TRANSLUCENT);
            lp.gravity=Gravity.END|Gravity.CENTER_VERTICAL; overlay=box; wm.addView(box,lp);
        } catch(Exception e) { Session.event(this,"overlay_failed",e.getClass().getSimpleName()+"；请用通知或返回记录器结束"); }
    }
    void release() {
        if(recorder!=null) { if(videoRunning) try { recorder.stop(); Session.event(this,"video_finalized","MP4已完成封装"); } catch(Exception e) { Session.event(this,"video_finalize_failed",e.getClass().getSimpleName()+"；MP4可能无法播放"); Session.status(this,"screenStatus","MP4封装失败，现有视频可能损坏"); } videoRunning=false; recorder.release(); recorder=null; }
        if(display!=null) { display.release(); display=null; }
        if(projection!=null) { projection.stop(); projection=null; }
    }
    void finish() {
        if(finishing) return; finishing=true;
        release(); Session.event(this,"session_stop","已停止；可填写备注并导出"); Session.status(this,"stoppedAt",Session.stamp()); Session.active=false; Session.paused=false;
        if(overlay!=null) { try { wm.removeView(overlay); } catch(Exception ignored) {} overlay=null; }
        stopForeground(STOP_FOREGROUND_REMOVE); handler.removeCallbacks(diskCheck);
        try { startActivity(new Intent(this,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_SINGLE_TOP)); } catch(Exception ignored) {}
        // Background activity starts may be blocked: leave a non-ongoing export notification.
        getSystemService(NotificationManager.class).notify(2,new Notification.Builder(this,"record").setSmallIcon(android.R.drawable.stat_sys_download_done).setContentTitle("记录已结束，点击填写备注并导出 ZIP").setContentIntent(PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT)).setAutoCancel(true).build());
        stopSelf();
    }
    public void onDestroy() { if(!finishing && Session.active) { Session.event(this,"service_destroyed","系统停止服务"); finishing=true; release(); Session.active=false; Session.status(this,"stoppedAt",Session.stamp()); } if(overlay!=null) try {wm.removeView(overlay);} catch(Exception ignored) {} handler.removeCallbacksAndMessages(null); super.onDestroy(); }
}
