package es.caib.seycon.idp.sse.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
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

import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SseReceiverMethod;
import com.soffid.iam.addons.federation.api.SseSubscription;
import com.soffid.iam.addons.federation.api.SubjectFormatEnumeration;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class VerifyEndpoint extends HttpServlet {
	/**
	 * 
	 */
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
        	IdpConfig c = IdpConfig.getConfig();

        	SseReceiver r = SseReceiverCache.instance().findBySecret(auth);
        	if (r == null) {
        		resp.setStatus(resp.SC_UNAUTHORIZED);
        		return;
        	}
        	
    		JSONObject request = new JSONObject(new JSONTokener(in));
    		String state = request.optString("state", null);
    		
    		SseEvent event = new SseEvent();
    		event.setReceiver(r.getName());
    		event.setDate(new Date());
    		event.setType(Events.VERIFY);
    		event.setSubject(state);
    		SseSender.instance().postMessage(event);
        	resp.setStatus(resp.SC_NO_CONTENT);
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
//		resp.addHeader("Access-Control-Allow-Origin", "*");
//		resp.addHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
//		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}

}