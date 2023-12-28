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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SseReceiverMethod;
import com.soffid.iam.addons.federation.api.SubjectFormatEnumeration;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class StreamEndpoint extends HttpServlet {
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
        	IdpConfig c = IdpConfig.getConfig();

        	SseReceiver r = SseReceiverCache.instance().findBySecret(auth);
        	if (r == null) {
        		resp.setStatus(resp.SC_UNAUTHORIZED);
        		return;
        	}

        	JSONObject o = generateStreamObject(r);
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
        	IdpConfig c = IdpConfig.getConfig();

        	SseReceiver r = SseReceiverCache.instance().findBySecret(auth);
        	if (r == null) {
        		resp.setStatus(resp.SC_UNAUTHORIZED);
        		return;
        	}

        	boolean anyChange = false;
    		JSONObject request = new JSONObject(new JSONTokener(in));
        	if (request.has("events_requested")) {
        		List l = request.getJSONArray("events_requested").toList();
        		if (! l.equals(r.getEvents())) {
        			r.setEvents(l);
        			anyChange = true;
        		}
        	}
        	if (request.has("delivery")) {
        		final JSONObject delivery = request.getJSONObject("delivery");
				String method = delivery.optString("method");
       			SseReceiverMethod m = 
       				"https://schemas.openid.net/secevent/risc/delivery-method/poll".equals(method) ? SseReceiverMethod.POLL :
       				"https://schemas.openid.net/secevent/risc/delivery-method/push".equals(method) ? SseReceiverMethod.PUSH :
       				null;
       			if (m != null && r.getMethod() != m) {
       				r.setMethod(m);
       				anyChange = true;
       			}
       			if (m == SseReceiverMethod.PUSH) {
       				String url = delivery.optString("url", null);
       				if (url != null)
       				{
       					r.setUrl(url);
       					anyChange = true;
       				}
       				String header = delivery.optString("authorization_header", null);
       				if (header != null)
       				{
       					r.setAuthorizationHeader(header);
       					anyChange = true;
       				}
       			}
        	}
        	if (request.has("format")) {
        		String format = request.optString("format");
        		SubjectFormatEnumeration e =
      				"account".equals(format) ? SubjectFormatEnumeration.ACCOUNT:
       				"did".equals(format) ? SubjectFormatEnumeration.DID:
       				"email".equals(format) ? SubjectFormatEnumeration.EMAIL:
       				"iss_sub".equals(format) ? SubjectFormatEnumeration.ISS_SUB:
      				"opaque".equals(format) ? SubjectFormatEnumeration.OPAQUE:
       				"phone_number".equals(format) ? SubjectFormatEnumeration.PHONE_NUMBER:
       				"uri".equals(format) ? SubjectFormatEnumeration.URI:
       				null;
        		if (e != null && r.getSubjectType() != e) {
        			r.setSubjectType(e);
        			anyChange = true;
        		}
        	}
    		
        	if (anyChange) {
		    	SharedSignalEventsService sseService = new RemoteServiceLocator().getSharedSignalEventsService();
		    	sseService.update(r);
		    	
        	}
        	JSONObject o = generateStreamObject(r);
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

	protected JSONObject generateStreamObject(SseReceiver r) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
    	IdpConfig c = IdpConfig.getConfig();
		
    	JSONObject o = new JSONObject();
		o.put("iss", r.getIdentityProvider());
		JSONArray aud = new JSONArray();
		aud.put(r.getName());
		o.put("aud", aud);
		JSONArray ev = new JSONArray();
		ev.put("");
		o.put("events_supported", new JSONArray(eventsList));
		o.put("events_requested", new JSONArray(r.getEvents()));
		JSONArray delivered = new JSONArray();
		for (String event: eventsList) {
			if (r.getEvents().contains(event))
				delivered.put(event);
		}
		o.put("events_delivered", delivered);
		if (r.getMethod() != null) {
			JSONObject d = new JSONObject();
			d.put("method", r.getMethod() == SseReceiverMethod.POLL ? "https://schemas.openid.net/secevent/risc/delivery-method/poll":
				r.getMethod() == SseReceiverMethod.PUSH ? "https://schemas.openid.net/secevent/risc/delivery-method/push":
					null);
			if (r.getMethod() == SseReceiverMethod.POLL) {
				final String portSuffix = c.getStandardPort() == 443 ? "":  ":"+c.getStandardPort();
				d.put("endpoint_url", "https://"+c.getHostName()+portSuffix+
						"/sse/poll");
			} else {
				d.put("endpoint_url", r.getUrl());
				d.put("authorization_header", r.getAuthorizationHeader());
			}
			o.put("delivery", d);
		}
		o.put("min_verification_interval", 1);
		if (r.getSubjectType() == SubjectFormatEnumeration.ISS_SUB)
			o.put("format", "iss_sub");
		else if (r.getSubjectType() == SubjectFormatEnumeration.ACCOUNT)
			o.put("format", "account");
		else if (r.getSubjectType() == SubjectFormatEnumeration.DID)
			o.put("format", "did");
		else if (r.getSubjectType() == SubjectFormatEnumeration.EMAIL)
			o.put("format", "email");
		else if (r.getSubjectType() == SubjectFormatEnumeration.OPAQUE)
			o.put("format", "opaque");
		else if (r.getSubjectType() == SubjectFormatEnumeration.PHONE_NUMBER)
			o.put("format", "phone_number");
		else if (r.getSubjectType() == SubjectFormatEnumeration.URI)
			o.put("format", "uri");
		return o;
	}

	protected static String[] eventsList = new String[] {
			Events.VERIFY,
			Events.CAEP_ASSURANCE_LEVEL_CHANGE,
			Events.CAEP_CREDENTIAL_CHANGE,
			Events.CAEP_DEVICE_COMPLIANCE_CHANGE,
			Events.CAEP_SESSION_REVOKED,
			Events.CAEP_TOKEN_CLAIMS_CHANGE,
			Events.RISC_ACCOUNT_DISABLED,
			Events.RISC_ACCOUNT_ENABLED,
			Events.RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED,
			Events.RISC_ACCOUNT_PURGED,
			Events.RISC_CREDENTIAL_COMPROMISED,
			Events.RISC_IDENTIFIER_CHANGED,
			Events.RISC_IDENTIFIER_RECYCLED,
			Events.RISC_RECOVERY_ACTIVATED,
			Events.RISC_RECOVERY_INFORMATION_CHANGED,
			Events.SOFFID_AUDIT,
			Events.SOFFID_LOG
		};
	

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

	@Override
	protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
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

        	r.getEvents().clear();
        	r.setMethod(null);
        	r.setSubjectType(null);
	    	SharedSignalEventsService sseService = new RemoteServiceLocator().getSharedSignalEventsService();
	    	sseService.update(r);
	    	sseService.clearSubscriptions(r);
	    	
	    	JSONObject o = generateStreamObject(r);
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
}
