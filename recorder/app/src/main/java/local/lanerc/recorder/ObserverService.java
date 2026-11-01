package local.lanerc.recorder;

import android.accessibilityservice.AccessibilityService;
import android.view.accessibility.*;
import android.graphics.Rect;
import org.json.*;

public class ObserverService extends AccessibilityService {
    static volatile boolean connected;
    private long lastTree;
    protected void onServiceConnected() { connected=true; if(Session.active) Session.event(this,"accessibility_connected","服务已连接"); }
    public void onDestroy() { connected=false; if(Session.active) Session.event(this,"accessibility_disconnected","服务断开，之后无法采集节点"); super.onDestroy(); }
    public void onInterrupt() { if(Session.active) Session.event(this,"accessibility_interrupt","无障碍服务中断"); }
    public void onAccessibilityEvent(AccessibilityEvent e) {
        if(!Session.active || Session.paused || !Session.TARGET.contentEquals(e.getPackageName()==null?"":e.getPackageName())) return;
        Session.event(this,"ui_event", "type="+e.getEventType()+"; password="+e.isPassword()+"; text=omitted");
        if(e.isPassword()) return;
        long now=android.os.SystemClock.elapsedRealtime();
        if(now-lastTree<1000 && e.getEventType()!=AccessibilityEvent.TYPE_VIEW_CLICKED) return;
        lastTree=now;
        AccessibilityNodeInfo root=getRootInActiveWindow();
        if(root==null) { Session.event(this,"nodes_unavailable","无可访问节点；Flutter/安全窗口可能限制读取"); return; }
        try {
            if(!Session.TARGET.contentEquals(root.getPackageName()==null?"":root.getPackageName())) return;
            JSONArray nodes=new JSONArray(); walk(root,nodes,0);
            Session.event(this,"node_snapshot",nodes.toString());
            Session.status(this,"accessibilityObserved",true);
        } catch(Exception ex) { Session.event(this,"node_error",ex.getClass().getSimpleName()); }
        finally { root.recycle(); }
    }
    private void walk(AccessibilityNodeInfo n, JSONArray list,int depth) throws Exception {
        if(depth>16 || list.length()>=150 || n.isPassword() || n.isEditable()) return;
        Rect r=new Rect(); n.getBoundsInScreen(r);
        JSONObject item=new JSONObject(); item.put("depth",depth); item.put("bounds",r.toShortString());
        item.put("clickable",n.isClickable()); item.put("children",n.getChildCount());
        // Deliberately omit className, viewId, text and contentDescription: all may contain app/user data.
        list.put(item);
        for(int i=0;i<Math.min(n.getChildCount(),50);i++) { AccessibilityNodeInfo child=n.getChild(i); if(child!=null) { try { walk(child,list,depth+1); } finally { child.recycle(); } } }
    }
}
