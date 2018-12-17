package es.caib.seycon.idp.openid.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
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
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
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
		if (grantType.equals("authorization_code"))
		{
			grantCode(req, resp, authorizationCode, authentication);
		} else if ("password".equals(grantType)) {
			passwordGrant(req, resp, authentication);
		}
	}

	private void passwordGrant(HttpServletRequest req, HttpServletResponse resp, String authentication) throws IOException {
		try {
			IdpConfig config = IdpConfig.getConfig();
			String user = req.getParameter("username");
			String password = req.getParameter("password");
			
			TokenHandler h = TokenHandler.instance();
			OpenIdRequest request = new OpenIdRequest();
			
			if (! authentication.toLowerCase().startsWith("Basic ") || !authentication.contains(":"))
			{
				buildError (resp, "Unauthorized");
				return;
			}
			String clientId = authentication.substring(6, authentication.indexOf(":"));
			request.setClientId(clientId);
			request.setFederationMember( config.getFederationService().findFederationMemberByClientID(request.getClientId()) );
			if (request.getFederationMember() == null)
			{
				buildError (resp, "Unauthorized");
				return;
			}
			Password pass = Password.decode(request.getFederationMember().getOpenidSecret());
			String expectedAuth = request.getFederationMember().getOpenidClientId()+":"+
					pass.getPassword();
			
			expectedAuth = "Basic "+Base64.encodeBytes( expectedAuth.getBytes("UTF-8"), Base64.DONT_BREAK_LINES );
			if (! expectedAuth.equalsIgnoreCase(authentication))
			{
				buildError (resp, "Wrong client credentials");
				return;
			}
	
			TokenInfo t = h.generateAuthenticationRequest(request , user);
						String redirectUri = req.getParameter("redirect_uri");
			if ( t.request.redirectUrl != null && ! t.request.redirectUrl.equals(redirectUri))
			{
				buildError(resp, "invalid_request_uri");
				return;
			}
			
			if (user == null || user.trim().isEmpty()) {
				buildError (resp, "Wrong user credentials");
				return;
			} else if ( password == null || password.trim().isEmpty() ) {
				buildError (resp, "Wrong user credentials");
				return;
			} else {
			    PasswordManager v = new PasswordManager();
	
			    try {
			        if (v.validate(user, new Password(password))) {
			            if (v.mustChangePassword()) {
			            	buildError(resp, "Password is expired");
			            	return;
			            }
			        }
			        else
			        {
			    		buildError (resp, "Wrong user credentials");
			    		return;
			        	
			        }
			    } catch (UnknownUserException e) {
					buildError (resp, "Wrong user credentials");
					return;
			    } catch (Exception e) {
					buildError (resp, "Wrong user credentials");
					log.warn("Error authenticating user credentials", e);
					return;
			    }
			}
	
			try {
				h.generateToken (t);
			} catch (Exception e) {
				log.info("Error generating token", e);
				buildError (resp, "Internal error "+e.toString());
				return;
			}
			
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
				buildError(resp, "Error resolving attributes");
				return;
			} catch (AttributeFilteringException e) {
				log.warn("Error filtering attributes", e);
				buildError(resp, "Error resolving attributes");
				return;
			} catch (InternalErrorException e) {
				log.warn("Error evaluating claims", e);
				buildError(resp, "Error resolving attributes");
				return;
			} catch (JSONException e) {
				log.warn("Error generating response", e);
				buildError(resp, "Error generating response");
				return;
			} catch (Throwable e) {
				log.warn("Error generating open id token", e);
				buildError(resp, "Error generating open id token");
				return;
			}
		} catch (Exception e) {
			log.warn("Internal error generating token", e);
			throw new IOException("Error generanting token", e);
		}
	}

	private void grantCode(HttpServletRequest req, HttpServletResponse resp, String authorizationCode,
			String authentication) throws IOException, ServletException, UnsupportedEncodingException {
		TokenHandler h = TokenHandler.instance();
		TokenInfo t = h.getAuthorizationCode (authorizationCode);
		if ( t == null)
		{
			buildError (resp, "Invalid authorization code");
			return;
		}
		
		Password pass = Password.decode(t.getRequest().getFederationMember().getOpenidSecret());
		
		String expectedAuth = t.getRequest().getFederationMember().getOpenidClientId()+":"+
				pass.getPassword();
		
		expectedAuth = "Basic "+Base64.encodeBytes( expectedAuth.getBytes("UTF-8"), Base64.DONT_BREAK_LINES );
		if (! expectedAuth.equalsIgnoreCase(authentication))
		{
			buildError (resp, "Wrong client credentials");
			return;
		}
		
		String redirectUri = req.getParameter("redirect_uri");
		if ( t.request.redirectUrl != null && ! t.request.redirectUrl.equals(redirectUri))
		{
			buildError(resp, "invalid_request_uri");
			return;
		}
		
		try {
			h.generateToken (t);
		} catch (Exception e) {
			log.info("Error generating token", e);
			buildError (resp, "Internal error "+e.toString());
			return;
		}
		
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
			buildError(resp, "Error resolving attributes");
			return;
		} catch (AttributeFilteringException e) {
			log.warn("Error filtering attributes", e);
			buildError(resp, "Error resolving attributes");
			return;
		} catch (InternalErrorException e) {
			log.warn("Error evaluating claims", e);
			buildError(resp, "Error resolving attributes");
			return;
		} catch (JSONException e) {
			log.warn("Error generating response", e);
			buildError(resp, "Error generating response");
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
