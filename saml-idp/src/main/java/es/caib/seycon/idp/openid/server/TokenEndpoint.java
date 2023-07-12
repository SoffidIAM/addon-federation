package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
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

import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.common.AllowedScope;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.FederationMemberSession;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.Session;
import com.soffid.iam.utils.ConfigurationCache;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class TokenEndpoint extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String authorizationCode = req.getParameter("code");
		String authentication = req.getHeader("Authorization");
		String grantType = req.getParameter("grant_type");
		if (grantType == null) {
			buildError(resp, "invalid_request", "Missing grant type parameter");
		} else if (grantType.equals("authorization_code")) {
			grantCode(req, resp, authorizationCode, authentication);
		} else if ("password".equals(grantType)) {
			passwordGrant(req, resp, authentication);
		} else if ("refresh_token".equals(grantType)) {
			refreshToken(req, resp, authentication);
		} else {
			buildError(resp, "invalid_request", "Invalid grant type " + grantType);
		}
	}

	private boolean isDebug() {
		return OidcDebugController.isDebug();
	}

	private void passwordGrant(HttpServletRequest req, HttpServletResponse resp, String authentication)
			throws IOException, ServletException {
		try {
			IdpConfig config = IdpConfig.getConfig();
			String username = req.getParameter("username");
			String password = req.getParameter("password");
			String clientId = req.getParameter("client_id");
			String clientSecret = req.getParameter("client_secret");

			if (isDebug()) {
				log.info("Received token request with password mechanism:");
				log.info("client_id     = "+clientId);
				log.info("client_secret = "+ofuscate(clientSecret));
				log.info("username      = "+username);
				log.info("password      = "+ofuscate(password));
				log.info("auth header   = "+ofuscate(authentication));
				log.info("scope         = "+req.getParameter("scope"));
			}

			TokenHandler h = TokenHandler.instance();
			OpenIdRequest request = new OpenIdRequest();
			req.getSession().setAttribute(SessionConstants.OPENID_REQUEST, request);
	    	
			if (authentication != null && authentication.toLowerCase().startsWith("basic ")) {
				String decoded = new String(Base64.decode(authentication.substring(6)), "UTF-8");
				String clientId2 = decoded.substring(0, decoded.indexOf(":"));
				if (clientId != null && !clientId.equals(clientId2)) {
					buildError(resp, "invalid_request", "Client id and credentials mismatch");
					return;
				} else {
					clientId = clientId2;
					clientSecret = decoded.substring(decoded.indexOf(":") + 1 );
					if (config.getFederationService().findFederationMemberByClientID(clientId) == null) {
						clientId = URLDecoder.decode(clientId, "UTF-8");
						clientSecret = URLDecoder.decode(clientSecret, "UTF-8");
					}
				}
			}
			request.setClientId(clientId);
			if (clientId == null || clientId.isEmpty()) {
				if (authentication == null) {
					resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					resp.setHeader("WWW-Authenticate", "Basic realm=\"Client credentials\"");
				} else {
					buildError(resp, "invalid_request", "Missing client id parameter");
				}
				return;
			}

			request.setFederationMember(
					config.getFederationService().findFederationMemberByClientID(request.getClientId()));
			if (request.getFederationMember() == null) {
				buildError(resp, "unauthorized_client", "Wrong client id");
				return;
			}
			
			// Check scope
			boolean found = false;
			request.setScope(req.getParameter("scope"));
	    	if (request.getScope() != null) {
		    	for (String s: request.getScope().split(" +"))
		    	{
		    		if (s.equalsIgnoreCase("openid")) found = true;
	        		for (AllowedScope scope: request.getFederationMember().getAllowedScopes()) {
	        			if (scope.getScope().equals("*") || scope.getScope().equals(s)) {
	        				found = true;
	        				break;
	        			}
	        		}
	        		if (!found) {
	        			buildError(resp, "invalid_scope", "The requested scope "+s+" is not allowed due to system policies");
	        			return;
	        		}
		    	}
	    	} else {
	    		found = true;
	    	}
	    	if (! found)
	    	{
	            buildError(resp, "invalid_scope", "The requested scope does not contain the scope openid: "+request.getScope());
	    	}

    		// Check authentication mechanism
			if (request.getFederationMember().getOpenidMechanism().contains("PA")) {
				// Accept request
				log.info("Accepted mechanism PA for " + request.getFederationMember().getPublicId());
			} else if (request.getFederationMember().getOpenidMechanism().contains("PC")) {
				Digest pass = request.getFederationMember().getOpenidSecret();
				if (clientId != null && clientSecret != null) {
					if (pass == null || ! pass.validate(clientSecret)) {
						buildError(resp, "invalid_client", "Wrong client credentials");
						return;
					}
				} else {
					if (authentication == null) {
						resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
						resp.setHeader("WWW-Authenticate", "Basic realm=\"Client credentials\"");
						return;
					}
					if (!validAuthentication(authentication, request.getFederationMember())) {
						buildError(resp, "invalid_client", "Wrong client credentials");
						return;
					}
				}
				log.info("Accepted mechanism PC for " + request.getFederationMember().getPublicId() + " / "
						+ authentication);
			} else {
				buildError(resp, "unsupported_grant_type", "Not authorized to use password grant type");
				return;
			}


			TokenInfo t;
			if (username == null || username.trim().isEmpty()) {
				AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
				if (ctx != null) {
					try {
						ctx.authenticationFailure(username, "Missing user name parameter");
					} catch (InternalErrorException e) {
					}
				}
				buildError(resp, "invalid_client", "Wrong user credentials. Missing username parameter");
				return;
			} else if (password == null || password.trim().isEmpty()) {
				AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
				if (ctx != null) {
					try {
						ctx.authenticationFailure(username, "Missing password parameter");
					} catch (InternalErrorException e) {
					}
				}
				buildError(resp, "invalid_client", "Wrong user credentials. Missing password parameter");
				return;
			} else {
				AuthenticationContext authCtx = new AuthenticationContext();
				authCtx.setPublicId(request.getFederationMember().getPublicId());
				authCtx.initialize(req);
				if (authCtx.getAllowedAuthenticationMethods().contains("P")) {
					PasswordManager v = new PasswordManager();

					LogRecorder logRecorder = LogRecorder.getInstance();
					if (v.validate(username, new Password(password))) {
						if (!v.mustChangePassword()) {
							logRecorder.addErrorLogEntry(username, Messages.getString("UserPasswordAction.7"), //$NON-NLS-1$
									req.getRemoteAddr());
							// 1. Mask the context as authenticated
							authCtx.authenticated(username, "P", resp);
							// 2. Register Soffid session
							Autenticator autenticator = new Autenticator();
							String oauthSessionId = autenticator.generateRandomSessionId();
							autenticator.generateSession(req, resp, username, authCtx.getUsedMethod(), false, oauthSessionId, null);
							// Generate token
							t = h.generateAuthenticationRequest(request, username, authCtx.getUsedMethod(), autenticator.getSession(req, true), oauthSessionId);
							t.setUser(username);
							t.setAuthenticationMethod("P");
							String scopes = config.getFederationService().filterScopes(request.getScope(), username, config.getSystem().getName(), request.getFederationMember().getPublicId());
							t.setScope(scopes);
						} else {
							authCtx.authenticationFailure(username, Messages.getString("UserPasswordAction.8"));
							logRecorder.addErrorLogEntry(username, Messages.getString("UserPasswordAction.8"), //$NON-NLS-1$
									req.getRemoteAddr());
							buildError(resp, "invalid_grant", "Password is expired");
							return;
						}
					} else {
						logRecorder.addErrorLogEntry(username, Messages.getString("UserPasswordAction.8"), //$NON-NLS-1$
								req.getRemoteAddr());
						buildError(resp, "invalid_grant", "Invalid username or password");
						return;
					}
				} else {
					buildError(resp, "invalid_request", "Password authentication is not allowed");
					return;
				}
			}

			Map<String, Object> att;
			try {
				att = new UserAttributesGenerator().generateAttributes(getServletContext(), t);
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
			} catch (Exception e) {
				log.warn("Error generating response", e);
				buildError(resp, "Error generating response", t);
				return;
			}
			try {
				h.generateToken(t, att, req, "P");
			} catch (Exception e) {
				log.info("Error generating token", e);
				buildError(resp, "server_error", "Internal error " + e.toString());
				return;
			}

			generatTokenResponse(req, resp, att, h, t);
		} catch (Exception e) {
			log.warn("Error generating token response", e);
			buildError(resp, e.toString());
		}
	}

	private void grantCode(HttpServletRequest req, HttpServletResponse resp, String authorizationCode,
			String authentication) throws IOException, ServletException, UnsupportedEncodingException {
		String clientId = req.getParameter("client_id");
		String clientSecret = req.getParameter("client_secret");
		TokenHandler h = TokenHandler.instance();
		TokenInfo t = null;
		try {
			if (isDebug()) {
				log.info("Received token request with grant code mechanism:");
				log.info("client_id          = "+clientId);
				log.info("client_secret      = "+ofuscate(clientSecret));
				log.info("authorization_code = "+ofuscate(authorizationCode));
				log.info("auth header        = "+ofuscate(authentication));
			}
			t = h.getAuthorizationCode(authorizationCode);
			if (t == null) {
				buildError(resp, "invalid_grant", "Invalid authorization code");
				return;
			}
			Digest pass = t.getRequest().getFederationMember().getOpenidSecret();
			
			if (pass == null) {
				if (!clientId.equals(t.getRequest().getFederationMember().getOpenidClientId())) {
					buildError(resp, "unauthorized_client", "Wrong client credentials", t);
					return;
				}
			} 
			else if (clientId != null && clientSecret != null) {
				if (!clientId.equals(t.getRequest().getFederationMember().getOpenidClientId())
						|| ! pass.validate(clientSecret)) {
					buildError(resp, "unauthorized_client", "Wrong client credentials", t);
					return;
				}
			} else {
				if (!validAuthentication(authentication, t.getRequest().getFederationMember())) {
					buildError(resp, "unauthorized_client", "Wrong client credentials", t);
					return;
				}
			}
			if (! checkPkceCode(t, req.getParameter("code_verifier"))) {
				buildError(resp, "unauthorized_client", "Wrong PKCE challenge", t);
				return;
			} 
			Map<String, Object> att;
			try {
				att = new UserAttributesGenerator().generateAttributes(getServletContext(), t);
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
			} catch (Exception e) {
				log.warn("Error generating response", e);
				buildError(resp, "Error generating response", t);
				return;
			}
			h.generateToken(t, att, req, "Authorization-code");
			generatTokenResponse(req, resp, att, h, t);
		} catch (Exception e) {
			log.info("Error generating token", e);
			buildError(resp, "Internal error " + e.toString(), t);
			return;
		}

	}

	private String ofuscate(String s) {
		return OidcDebugController.ofuscate(s);
	}

	private boolean validAuthentication(String authentication, FederationMember federationMember) throws UnsupportedEncodingException {
		if (!authentication.toLowerCase().startsWith("basic "))
			return false;
		
		String rest = new String (java.util.Base64.getDecoder().decode(authentication.substring(6)), StandardCharsets.UTF_8);
		
		String ci = rest.substring(0, rest.indexOf(":"));
		String cs = rest.substring(rest.indexOf(":")+1);
		if ( ! rest.startsWith(federationMember.getOpenidClientId()+":") &&
				! URLDecoder.decode(ci, "UTF-8").equals(federationMember.getOpenidClientId()))
			return false;
		
		return federationMember.getOpenidSecret().validate(cs) ||
				federationMember.getOpenidSecret().validate(URLDecoder.decode(cs, "UTF-8")) ;
	}

	private boolean checkPkceCode(TokenInfo t, String parameter) throws NoSuchAlgorithmException {
		if (t.getPkceChallenge() == null)
			return true;
		
		if (parameter == null)
			return false;
		
		if ("S256".equals(t.getPkceAlgorithm())) {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] encodedhash = digest.digest(parameter.getBytes(StandardCharsets.UTF_8));
			parameter = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(encodedhash);
		}
		
		return (parameter.equals(t.getPkceChallenge()));
	}

	private void refreshToken(HttpServletRequest req, HttpServletResponse resp, String authentication)
			throws IOException, ServletException, UnsupportedEncodingException {
		String refreshToken = req.getParameter("refresh_token");

		String clientId = req.getParameter("client_id");
		String clientSecret = req.getParameter("client_secret");

		TokenHandler h = TokenHandler.instance();
		TokenInfo t = null;
		try {
			if (isDebug()) {
				log.info("Received token request with refresh mechanism:");
				log.info("client_id     = "+clientId);
				log.info("client_secret = "+ofuscate(clientSecret));
				log.info("refresh token = "+refreshToken);
				log.info("auth header   = "+ofuscate(authentication));
			}
			t = h.getRefreshToken(refreshToken);
			if (t == null) {
				buildError(resp, "invalid_grant", "Invalid refresh token");
				return;
			}

			FederationMember federationMember = t.getRequest().getFederationMember();
			Digest pass = federationMember.getOpenidSecret();

			if (pass == null) {
				if (!clientId.equals(t.getRequest().getFederationMember().getOpenidClientId())) {
					buildError(resp, "unauthorized_client", "Wrong client credentials", t);
					return;
				}
			} 
			else if (clientId != null && clientSecret != null) {
				if (!clientId.equals(t.getRequest().getFederationMember().getOpenidClientId())
						|| ! pass.validate(clientSecret)) {
					buildError(resp, "unauthorized_client", "Wrong client credentials", t);
					return;
				}
			} else {
				if (!validAuthentication(authentication, federationMember)) {
					buildError(resp, "unauthorized_client", "Wrong client credentials", t);
					return;
				}
			}

			Map<String, Object> att;
			try {
				att = new UserAttributesGenerator().generateAttributes(getServletContext(), t);
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
			} catch (Exception e) {
				log.warn("Error generating response", e);
				buildError(resp, "Error generating response", t);
				return;
			}
			h.renewToken(t, att, req);
		} catch (Exception e) {
			log.info("Error generating token", e);
			buildError(resp, "Internal error " + e.toString(), t);
			return;
		}

		Map<String, Object> att;
		try {
			att = new UserAttributesGenerator().generateAttributes(getServletContext(), t);
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
		} catch (Exception e) {
			log.warn("Error generating response", e);
			buildError(resp, "Error generating response", t);
			return;
		}
		t.request.setNonce(null);
		generatTokenResponse(req, resp, att, h, t);
	}

	private void generatTokenResponse(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> att, TokenHandler h, TokenInfo t)
			throws IOException, ServletException {
		try {
			String token = h.generateIdToken(t, att, req.getRequestURI().contains("/auth/realms/soffid/"));
			JSONObject o = new JSONObject();
			o.put("access_token", t.token);
			o.put("token_type", "Bearer");
			o.put("refresh_token", t.refreshTokenFull);
			o.put("expires_in", (t.expires - System.currentTimeMillis()) / 1000);
			o.put("id_token", token);
			if (isDebug()) {
				log.info("Sending response");
				log.info("access_token  = "+t.token);
				log.info("refresh_token = "+t.refreshToken);
				log.info("id_token      = "+token);
				log.info("expires_in    = "+ new Date(t.expires).toString());
			}
			buildResponse(resp, o);
		} catch (Throwable e) {
			log.warn("Error generating open id token", e);
			buildError(resp, "Error generating open id token", t);
			return;
		}
	}

	private void buildError(HttpServletResponse resp, String string) throws IOException, ServletException {
		buildError(resp, "server_error", string, null);
	}

	private void buildError(HttpServletResponse resp, String string, TokenInfo ti)
			throws IOException, ServletException {
		buildError(resp, "server_error", string, ti);
	}

	private void buildError(HttpServletResponse resp, String error, String description)
			throws IOException, ServletException {
		buildError(resp, error, description, null);
	}

	private void buildError(HttpServletResponse resp, String error, String description, TokenInfo ti)
			throws IOException, ServletException {
		JSONObject o = new JSONObject();
		try {
			o.put("error", error);
			o.put("error_description", description);
			if (ti != null && ti.request != null && ti.request.state != null)
				o.put("state", ti.request.state);
		} catch (JSONException e) {
			throw new ServletException("Error generating error message " + description, e);
		}
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(400);
		ServletOutputStream out = resp.getOutputStream();
		out.print(o.toString());
		out.close();
		if (isDebug()) {
			log.info("Sending back error "+error+": "+description);
		}
	}

	private void buildResponse(HttpServletResponse resp, JSONObject o) throws IOException {
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(200);
		ServletOutputStream out = resp.getOutputStream();
		out.print(o.toString());
		out.close();
	}

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
		resp.addHeader("Access-Control-Allow-Headers", "Authorization");
		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}

}
