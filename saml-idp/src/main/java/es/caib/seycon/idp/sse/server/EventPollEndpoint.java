package es.caib.seycon.idp.sse.server;

import java.io.IOException;
import java.io.PrintStream;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.json.JSONWriter;

import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class EventPollEndpoint extends HttpServlet {
	Log log = LogFactory.getLog(getClass());

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		JSONObject request = new JSONObject(new JSONTokener(req.getInputStream()));
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(200);
		SseReceiver r = null;
		
        try {
        	final SharedSignalEventsService svc = new RemoteServiceLocator().getSharedSignalEventsService();
        	String auth = req.getHeader("Authorization");
        	IdpConfig c = IdpConfig.getConfig();

        	r = SseReceiverCache.instance().findBySecret(auth);
        	if (r == null) {
        		resp.setStatus(resp.SC_UNAUTHORIZED);
        		return;
        	}
        	
        	if (r.isPause()) {
        		buildError(resp, "Stream is paused");
        		return;
        	}

        	int max = request.optInt("maxEvents", -1);
        	boolean wait = ! request.optBoolean("returnImmediately", true);
        	JSONArray ack = request.optJSONArray("ack");
        	if (ack != null) {
        		for (int i = 0; i < ack.length(); i++) {
        			Object o = ack.get(i);
        			if (o != null) {
        				try {
	        				svc.removeEvent(Long.parseLong(o.toString()) );
        				} catch (NumberFormatException e) {}
        			}
        		}
        	}
        	JSONObject errors = request.optJSONObject("setErrs");
        	if (errors != null) {
        		for (String o: errors.keySet()) {
    				try {
        				svc.removeEvent(Long.getLong(o.toString()) );
    				} catch (NumberFormatException e) {}
        		}
        	}
        			
        	boolean moreAvailable = false;;
        	LinkedList<SseEvent> l = null;
        	int s = 0;
        	do {
        		if (s++ > 0) {
        			Thread.sleep(100);
        		}
				l = new LinkedList<>( svc.fetchEvents(r, max < 0? null: max + 1) );
        	} while (l.isEmpty() && wait && s < 50) ;
        	if (max >= 0 && l.size() > max) {
        		l.removeLast();
        		moreAvailable = true;
        	}
        	SseSender sender = new SseSender();
        	
        	resp.setContentType("application/json");
        	ServletOutputStream out = resp.getOutputStream();
        	JSONWriter w = new JSONWriter(new PrintStream(out));
        	w.object();
        		w.key("sets");
        		w.object();
        		if (l != null) {
	        		for (SseEvent event: l) {
	        			if (sender.applies(r, event, getServletContext())) {
	        				w.key(event.getId().toString());
	        				w.value(sender.generateSET(event, getServletContext()));
	        			} else {
	        				svc.removeEvent(event.getId());
	        			}
	        		}
        		}
        		w.endObject();
        		w.key("moreAvailable");
        		w.value(moreAvailable);
        	w.endObject();
			return;
		} catch (Throwable e) {
			log.warn("Error polling events for "+(r == null? "unknown": r.getName()), e);
			buildError(resp, "Error fetching events");
			return;
		}

	}
	private void buildError(HttpServletResponse resp, String string) throws IOException, ServletException {
		JSONObject o = new JSONObject();
		try {
			o.put("error", string);
		} catch (JSONException e) {
			throw new ServletException("Error generating error message "+string, e);
		}
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.addHeader("WWW-Authenticate", "error=\"unexpected_error\",error_description=\""+string+"\"");
		resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		ServletOutputStream out = resp.getOutputStream();
		out.print( o.toString() );
		out.close();
	}

}
