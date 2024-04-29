package es.caib.seycon.idp.sse.server;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.api.SseReceiver;

import es.caib.seycon.ng.exception.InternalErrorException;

public class VerifyEndpoint extends SharedSignalsHttpServlet {

	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		ServletInputStream in = req.getInputStream();
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
        try {
        	String auth = req.getHeader("Authorization");
        	if (auth==null || !auth.toLowerCase().startsWith("bearer ")) {
    			resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    			return;
    		}

        	SseReceiver r = SseReceiverCache.instance().findBySecret(auth);
        	if (r == null) {
        		resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        		return;
        	}
        	
    		JSONObject request = new JSONObject(new JSONTokener(in));
    		String state = request.optString("state", null);
    		
    		if (isSSF()) {
    			boolean found = false;
    			try {
    				long stream_id = request.getLong("stream_id");
        			if (r.getId().longValue()==stream_id)
        				found = true;
    			} finally {
    				if (!found) {
        				resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
        				return;
    				}
    			}
    		}

    		SseEvent event = new SseEvent();
    		event.setReceiver(r.getName());
    		event.setDate(new Date());
    		event.setType(isSSE() ? Events.VERIFY_SSE : Events.VERIFY_SSF);
    		event.setSubject(state);
    		SseSender.instance().postMessage(event);
        	resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
		} catch (InternalErrorException e) {
			log.warn("Error evaluating claims", e);
			buildError(resp, "Error resolving attributes");
			return;
		} catch (Throwable e) {
			log.warn("Error generating open id token", e);
			buildError(resp, "Error generating open id token");
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

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		super.service(req, resp);
	}
}
