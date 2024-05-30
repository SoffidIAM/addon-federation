package es.caib.seycon.idp.sse.server;

import java.io.IOException;

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

import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class StatusEndpoint extends SharedSignalsHttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
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

    		if (isSSF()) {
    			String stream_id = req.getParameter("stream_id");
    			boolean found = false;
    			if (stream_id!=null) {
    				try {
    					if (r.getId().longValue()==Long.parseLong(stream_id))
    						found = true;
    				} catch(Exception e) {}
    			}
    			if (!found) {
					resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
					return;
				}
    		}

        	JSONObject o = generateStatusObject(r);
			buildResponse(resp, o);
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

        	IdpConfig c = IdpConfig.getConfig();

        	SseReceiver r = SseReceiverCache.instance().findBySecret(auth);
        	if (r == null) {
        		resp.setStatus(resp.SC_UNAUTHORIZED);
        		return;
        	}

    		JSONObject request = new JSONObject(new JSONTokener(in));

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

        	if (request.has("status")) {
        		final boolean pause = "paused".equals(request.optString("status"));
        		if (pause != r.isPause()) {
					r.setPause(pause);
					r.setStatusReason(request.has("reason") ? request.optString("reason") : null);
			    	SharedSignalEventsService sseService = new RemoteServiceLocator().getSharedSignalEventsService();
			    	sseService.update(r);
		        	JSONObject o = generateStatusObject(r);
					buildResponse(resp, o);
        		} else {
        			buildError(resp, HttpServletResponse.SC_BAD_REQUEST, "Status is the same than the current value");
        		}
        	} else {
        		buildError(resp, HttpServletResponse.SC_BAD_REQUEST, "Status is mandatory");
        	}


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

	protected JSONObject generateStatusObject(SseReceiver r) {
		JSONObject o = new JSONObject();
		if (isSSE()) {
			o.put("status", r.isPause() ? "paused" : "enabled");
		} else {
			o.put("stream_id", r.getId());
			o.put("status", r.isPause() ? "paused" : "enabled");
			if (r.getStatusReason()!=null && !r.getStatusReason().trim().isEmpty())
				o.put("reason", r.getStatusReason());
		}
		return o;
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

	private void buildError(HttpServletResponse resp, int HTTPCode, String string) throws IOException, ServletException {
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
		resp.setStatus(HTTPCode);
		ServletOutputStream out = resp.getOutputStream();
		out.print(o.toString());
		out.close();
	}

	private void buildResponse (HttpServletResponse resp, JSONObject o) throws IOException {
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(200);
		ServletOutputStream out = resp.getOutputStream();
		out.print( o.toString() );
		out.close();
	}
	
	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}
}
