package local.lanerc.recorder;

import android.app.*;
import android.content.*;
import android.os.*;
import android.view.accessibility.AccessibilityNodeInfo;
import java.io.*;
import java.util.zip.*;

/** Device-side tests without test SDKs, Google services, or network. */
public class SmokeInstrumentation extends Instrumentation {
    MainActivity activity;
    public void onCreate(Bundle args) { super.onCreate(args); start(); }
    void check(boolean value,String message) { if(!value) throw new AssertionError(message); }
    void waitFor(java.util.concurrent.Callable<Boolean> ready,String message) throws Exception {
        for(int i=0;i<60;i++) { if(ready.call()) return; SystemClock.sleep(200); }
        throw new AssertionError(message);
    }
    boolean clickSystem(String text) {
        AccessibilityNodeInfo root=getUiAutomation().getRootInActiveWindow(); if(root==null) return false;
        try { for(AccessibilityNodeInfo n:root.findAccessibilityNodeInfosByText(text)) { if(n.isClickable() && n.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return true; } return false; }
        finally { root.recycle(); }
    }
    void begin() { runOnMainSync(()->activity.begin(true)); }
    void stopCapture() throws Exception {
        getTargetContext().startService(new Intent(getTargetContext(),CaptureService.class).setAction(CaptureService.STOP));
        waitFor(()->!Session.active,"stop did not complete");
    }
    public void onStart() {
        Bundle result=new Bundle();
        try {
            activity=(MainActivity)startActivitySync(new Intent(getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            Session.delete(getTargetContext());
            begin(); waitFor(()->clickSystem("Cancel"),"projection denial dialog missing");
            waitFor(()->Session.meta(getTargetContext()).optString("screenStatus").contains("用户未授权"),"denial not reported");
            check(!Session.file(getTargetContext(),"screen.mp4").exists(),"denial produced video");
            stopCapture();
            File z=Session.zip(getTargetContext(),"emulator denial test");
            try(ZipFile zip=new ZipFile(z)) { check(zip.getEntry("report.txt")!=null,"report missing"); check(zip.getEntry("events.jsonl")!=null,"events missing"); check(zip.getEntry("screen.mp4")==null,"fake video"); }
            Session.delete(getTargetContext());
            runOnMainSync(()->activity.startActivity(new Intent(activity,MainActivity.class)));
            begin(); waitFor(()->clickSystem("Start now"),"projection approval dialog missing");
            waitFor(()->Session.meta(getTargetContext()).optString("screenStatus").startsWith("已启动"),"video failed to start");
            SystemClock.sleep(1800);
            getTargetContext().startService(new Intent(getTargetContext(),CaptureService.class).setAction(CaptureService.PAUSE));
            waitFor(()->Session.paused,"pause failed");
            getTargetContext().startService(new Intent(getTargetContext(),CaptureService.class).setAction(CaptureService.PAUSE));
            waitFor(()->!Session.paused,"resume failed");
            SystemClock.sleep(1000);
            // Android 11 system revocation through media_projection shell command.
            getUiAutomation().executeShellCommand("cmd media_projection stop").close();
            waitFor(()->!Session.active,"system interruption not handled");
            check(Session.file(getTargetContext(),"screen.mp4").length()>0,"video empty");
            File videoZip=Session.zip(getTargetContext(),"emulator recording interruption test");
            try(ZipFile zip=new ZipFile(videoZip)) { check(zip.getEntry("screen.mp4")!=null,"video absent from zip"); }
            result.putString("stream","PASS: Android 11 projection denial, grant, pause/resume, system interruption, ZIP contents. SAF UI, target app and secure windows not verified.\n");
            finish(Activity.RESULT_OK,result);
        } catch(Throwable e) {
            result.putString("stream","FAIL: "+android.util.Log.getStackTraceString(e)); finish(Activity.RESULT_CANCELED,result);
        }
    }
}
