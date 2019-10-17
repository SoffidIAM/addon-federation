package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.api.Password;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class TokenEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		String authorizationCode = req.getParameter("code");
		String authentication = req.getHeader("Authorization");
		String grantType = req.getParameter("grant_type");
		if (grantType == null)
		{
			buildError (resp, "invalid_request", "Missing grant type parameter");
		}
		else if (grantType.equals("authorization_code"))
		{
			grantCode(req, resp, authorizationCode, authentication);
		} else if ("password".equals(grantType)) {
			passwordGrant(req, resp, authentication);
		}
		else
		{
			buildError (resp, "invalid_request", "Invalid grant type "+grantType);
		}
	}

	private void passwordGrant(HttpServletRequest req, HttpServletResponse resp, String authentication) throws IOException, ServletException {
		try {
			IdpConfig config = IdpConfig.getConfig();
			String username = req.getParameter("username");
			String password = req.getParameter("password");
			String clientId = req.getParameter("client_id");
			String clientSecret = null;

			TokenHandler h = TokenHandler.instance();
			OpenIdRequest request = new OpenIdRequest();
			
			if (authentication != null &&
					authentication.toLowerCase().startsWith("basic "))
			{
				String decoded = new String (Base64.decode(authentication.substring(6)), "UTF-8");
				String clientId2 = decoded.substring(0, decoded.indexOf(":"));
				if (clientId != null && ! clientId.equals(clientId2))
				{
					buildError (resp, "invalid_request", "Client id and credentials mismatch");
					return;
				}
				else
					clientId = clientId2;
			}
			request.setClientId(clientId);
			if (clientId == null || clientId.isEmpty())
			{
				if (authentication == null)
				{
					resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					resp.setHeader("WWW-Authenticate", "Basic realm=\"Client credentials\"");
				}
				else
				{
					buildError (resp, "invalid_request", "Missing client id parameter");
				}
				return;
			}

			request.setFederationMember( config.getFederationService().findFederationMemberByClientID(request.getClientId()) );
			if (request.getFederationMember() == null)
			{
				buildError (resp, "unauthorized_client", "Wrong client id");
				return;
			}

			if (request.getFederationMember().getOpenidMechanism().contains("PA")) {
				// Accept request
				log.info("Accepted mechanism PA for "+request.getFederationMember().getPublicId());
			} 
			else if (request.getFederationMember().getOpenidMechanism().contains("PC"))
			{
				if (authentication == null)
				{
					resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					resp.setHeader("WWW-Authenticate", "Basic realm=\"Client credentials\"");
					return;
				}
				Password pass = Password.decode(request.getFederationMember().getOpenidSecret());
				String expectedAuth = request.getFederationMember().getOpenidClientId()+":"+
						pass.getPassword();
				
				expectedAuth = Base64.encodeBytes( expectedAuth.getBytes("UTF-8"), Base64.DONT_BREAK_LINES );
				if (!authentication.toLowerCase().startsWith("basic ") ||
						! expectedAuth.equals(authentication.substring(6)))
				{
					buildError (resp, "invalid_client", "Wrong client credentials");
					return;
				}
				log.info("Accepted mechanism PC for "+request.getFederationMember().getPublicId()+" / "+authentication);
			} else {
				buildError (resp, "unsupported_grant_type", "Not authorized to use password grant type");
				return;				
			}
			
			TokenInfo t = h.generateAuthenticationRequest(request , username);
			String redirectUri = req.getParameter("redirect_uri");
			if (username == null || username.trim().isEmpty()) {
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	    		if (ctx != null)
	    		{
	    			try {
						ctx.authenticationFailure();
					} catch (InternalErrorException e) {
					}
	    		}
				buildError (resp, "invalid_client", "Wrong user credentials. Missing username parameter");
				return;
			} else if ( password == null || password.trim().isEmpty() ) {
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	    		if (ctx != null)
	    		{
	    			try {
						ctx.authenticationFailure();
					} catch (InternalErrorException e) {
					}
	    		}
				buildError (resp, "invalid_client", "Wrong user credentials. Missing password parameter");
				return;
			} else {
				AuthenticationContext authCtx = new AuthenticationContext();
				authCtx.setPublicId(request.getFederationMember().getPublicId());
				authCtx.initialize(req);
				if (authCtx.getAllowedAuthenticationMethods().contains("P"))
				{
		            PasswordManager v = new PasswordManager();

		            LogRecorder logRecorder = LogRecorder.getInstance();
		            if (v.validate(username, new Password(password))) {
		            	if (!v.mustChangePassword()) {
		                    logRecorder.addErrorLogEntry(username, Messages.getString("UserPasswordAction.7"), req.getRemoteAddr()); //$NON-NLS-1$
			            	authCtx.authenticated(username, "P", resp);
			            	t.setUser(username);
			            	t.setAuthenticationMethod("P");
			            	
		            	} else {
		            		authCtx.authenticationFailure();
		                    logRecorder.addErrorLogEntry(username, Messages.getString("UserPasswordAction.8"), req.getRemoteAddr()); //$NON-NLS-1$
		                    buildError(resp, "invalid_grant", "Password is expired");
		                    return;
		                }
		            } else {
		                logRecorder.addErrorLogEntry(username, Messages.getString("UserPasswordAction.8"), req.getRemoteAddr()); //$NON-NLS-1$
		                buildError(resp, "invalid_grant", "Invalid username or password");
		                return;
		            }
				}
				else
				{
					buildError (resp, "invalid_request", "Password authentication is not allowed");
					return;
				}
			}
	
			try {
				h.generateToken (t);
			} catch (Exception e) {
				log.info("Error generating token", e);
				buildError (resp, "server_error", "Internal error "+e.toString());
				return;
			}
			
			generatTokenResponse(resp, h, t);
		} catch (Exception e) {
			log.warn("Error generating token response", e);
			buildError(resp, e.toString());
		}
	}

	private void grantCode(HttpServletRequest req, HttpServletResponse resp, String authorizationCode,
			String authentication) throws IOException, ServletException, UnsupportedEncodingException {
		TokenHandler h = TokenHandler.instance();
		TokenInfo t = h.getAuthorizationCode (authorizationCode);
		if ( t == null)
		{
			buildError (resp, "invalid_grant", "Invalid authorization code");
			return;
		}
		
		Password pass = Password.decode(t.getRequest().getFederationMember().getOpenidSecret());
		
		String expectedAuth = t.getRequest().getFederationMember().getOpenidClientId()+":"+
				pass.getPassword();
		
		expectedAuth = "Basic "+Base64.encodeBytes( expectedAuth.getBytes("UTF-8"), Base64.DONT_BREAK_LINES );
		if (! expectedAuth.equals(authentication))
		{
			buildError (resp, "unauthorized_client", "Wrong client credentials", t);
			return;
		}
		
		try {
			h.generateToken (t);
		} catch (Exception e) {
			log.info("Error generating token", e);
			buildError (resp, "Internal error "+e.toString(), t);
			return;
		}
		
		generatTokenResponse(resp, h, t);
	}

	private void generatTokenResponse(HttpServletResponse resp, TokenHandler h, TokenInfo t)
			throws IOException, ServletException {
		Map<String, Object>att  ;
		try {
			att = new UserAttributesGenerator().generateAttributes ( getServletContext(), t );
			String token = h.generateIdToken (t, att);
			JSONObject o = new JSONObject();
			o.put("access_token", t.token);
			o.put("token_type", "Bearer");
			o.put("refresh_token", t.refreshToken);
			o.put("expires_in", (t.expires - System.currentTimeMillis()) / 1000);
			o.put("id_token", token);
			buildResponse(resp, o);
		} catch (AttributeResolutionException e) {
			log.warn("Error resolving attributes", e);
			buildError(resp, "Error resolving attributes", t);
			return;
		} catch (AttributeFilteringException e) {
			log.warn("Error filtering attributes", e);
			buildError(resp, "Error resolving attributes", t);
			return;
		} catch (InternalErrorException e) {
			log.warn("Error evaluating claims", e);
			buildError(resp, "Error resolving attributes", t);
			return;
		} catch (JSONException e) {
			log.warn("Error generating response", e);
			buildError(resp, "Error generating response", t);
			return;
		} catch (Throwable e) {
			log.warn("Error generating open id token", e);
			buildError(resp, "Error generating open id token", t);
			return;
		}
	}

	private void buildError(HttpServletResponse resp, String string) throws IOException, ServletException {
		buildError(resp, "server_error", string, null);
	}

	private void buildError(HttpServletResponse resp, String string, TokenInfo ti) throws IOException, ServletException {
		buildError(resp, "server_error", string, ti);
	}

	private void buildError(HttpServletResponse resp, String error, String description) throws IOException, ServletException {
		buildError(resp, error, description, null);
	}

	private void buildError(HttpServletResponse resp, String error, String description, TokenInfo ti) throws IOException, ServletException {
		JSONObject o = new JSONObject();
		try {
			o.put("error", error);
			o.put("error_description", description);
			if (ti != null && ti.request != null && ti.request.state != null)
				o.put("state", ti.request.state);
		} catch (JSONException e) {
			throw new ServletException("Error generating error message "+description, e);
		}
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(400);
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

}
