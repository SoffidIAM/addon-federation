package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.sync.service.ServerService;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthorizationHandler;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class AuthorizationResponse  {
	static Log log = LogFactory.getLog(AuthorizationResponse.class);
	
	public static void generateResponse (ServletContext ctx, HttpServletRequest request, HttpServletResponse response, String authType, String sessionHash) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException
	{
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		log.info("Generating openid response");
		if (!checkAuthorization(user, r)) {
			log.info("Not authorized to login");
			unauthorized(request, response, r, user);
		} else if ( r.getResponseTypeSet().contains("code")) {
			log.info("Returnig authorization flow");
			authorizationFlow (request, response, authType, sessionHash);			
		} else {
			log.info("Returnig implicit flow");
			implicitFLow (ctx, request, response, authType, sessionHash);
		}
	}

	private static void unauthorized(HttpServletRequest request, HttpServletResponse response, OpenIdRequest r, String user) throws UnsupportedEncodingException, IOException {
   		response.sendRedirect(r.getRedirectUrl() + (r.getRedirectUrl().contains("?") ? "&": "?") +"error=access_denied&error_description="+
    				URLEncoder.encode("Access denied for user "+user , "UTF-8")+
    				(r.getState() != null ? "&state="+r.getState(): ""));
	}

	private static boolean checkAuthorization(String user, OpenIdRequest r) throws InternalErrorException, UnknownUserException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		FederationService fs = new RemoteServiceLocator().getFederacioService();
    	FederationMember member = fs.findFederationMemberByClientID(r.getClientId());
    	return new AuthorizationHandler().checkAuthorization(user, member);
	}

	private static void implicitFLow(ServletContext ctx, HttpServletRequest request, HttpServletResponse response, String authType, String sessionHash) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		TokenHandler h = TokenHandler.instance();
		TokenInfo token = h.generateAuthenticationRequest(r, user, authType, new Autenticator().getSession(request, true), sessionHash);
		final IdpConfig config = IdpConfig.getConfig();
		String scopes = config.getFederationService().filterScopes(r.getScope(), user, config.getSystem().getName(), r.getFederationMember().getPublicId());
		token.setScope(scopes);
		String authenticationMethod = (String) s.getAttribute(SessionConstants.AUTHENTICATION_USED);
		token.setAuthenticationMethod(authenticationMethod);
		Map<String, Object> att;
		try {
			att = new UserAttributesGenerator().generateAttributes(ctx, token);
		} catch (AttributeResolutionException e) {
			log.warn("Error resolving attributes", e);
			buildError(response, r, "Error resolving attributes");
			return;
		} catch (AttributeFilteringException e) {
			log.warn("Error filtering attributes", e);
			buildError(response, r, "Error resolving attributes");
			return;
		} catch (InternalErrorException e) {
			log.warn("Error evaluating claims", e);
			buildError(response, r, "Error resolving attributes");
			return;
		} catch (Exception e) {
			log.warn("Error generating response", e);
			buildError(response, r, "Error generating response");
			return;
		}

		h.generateToken (token, att, request, "Authorization-code");
		
		try {
			String openidToken = h.generateIdToken (token, att, request.getRequestURI().contains("/auth/realms/soffid/"));
			StringBuffer sb = new StringBuffer();
			String url = r.getRedirectUrl();
			if ((url == null || url.isEmpty()) && ! r.getFederationMember().getOpenidUrl().isEmpty())
				url = r.getFederationMember().getOpenidUrl().iterator().next();
			if (url != null && ! url.isEmpty())
			{
				LinkedList<String> args = new LinkedList<String> ();
				if (r.getResponseType().contains("code"))
					args.add("code=" + URLEncoder.encode(  token.authorizationCode) );
				if ( r.getResponseTypeSet().contains("token") )
				{
					args.add("access_token=" + URLEncoder.encode(  token.token) );
					args.add("token_type=bearer");
					args.add("expires_in=" +  (token.expires - System.currentTimeMillis()) / 1000);
				}
				if (r.getResponseTypeSet().contains("id_token"))
					args.add("id_token=" + URLEncoder.encode(openidToken , "UTF-8"));
				if ( r.getState() != null)
					args.add("state=" + URLEncoder.encode(r.getState() , "UTF-8"));
				sb.append("&session_state=active");
				boolean first = true;
				sb.append(url);
				for ( String arg: args)
				{
					if (first && !url.contains("?")) sb.append('?');
					else sb.append('&');
					sb.append(arg);
					first = false;
				}
				
				response.sendRedirect(sb.toString());
			} else {
				ServletOutputStream out = response.getOutputStream();
				response.setContentType("text/plain");
				out.println("Authorization code: "+token.authorizationCode);
				out.println("State: "+r.getState());
			}
			
		} catch (InternalErrorException e) {
			log.warn("Error evaluating claims", e);
			buildError(response, r, "Error resolving attributes");
			return;
		} catch (JSONException e) {
			log.warn("Error generating response", e);
			buildError(response, r, "Error generating response");
			return;
		} catch (Throwable e) {
			log.warn("Error generating open id token", e);
			buildError(response, r, "Error generating open id token");
			return;
		}


		
	}

	private static void buildError(HttpServletResponse resp, OpenIdRequest r, String description) throws IOException, ServletException {
		StringBuffer sb = new StringBuffer(r.getRedirectUrl());
		if (r.getRedirectUrl().contains("?"))
			sb.append("&");
		else
			sb.append("?");
		sb.append("error=server_error&error_description=")
			.append(URLEncoder.encode(description, "UTF-8"));
		if (r.getState() != null)
			sb.append("&state="+r.getState());
		resp.sendRedirect(sb.toString());
	}

	private static void authorizationFlow(HttpServletRequest request, HttpServletResponse response, String authType, String sessionHash) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		TokenHandler h = TokenHandler.instance();
		TokenInfo token = h.generateAuthenticationRequest(r, user, authType, new Autenticator().getSession(request, true), sessionHash);
		final IdpConfig config = IdpConfig.getConfig();
		String scopes = config.getFederationService().filterScopes(r.getScope(), user, config.getSystem().getName(), r.getFederationMember().getPublicId());
		token.setScope(scopes);
		String authenticationMethod = (String) s.getAttribute(SessionConstants.AUTHENTICATION_USED);
		token.setAuthenticationMethod(authenticationMethod);
		
		StringBuffer sb = new StringBuffer();
		String url = r.getRedirectUrl();
		if ((url == null || url.isEmpty()) && ! r.getFederationMember().getOpenidUrl().isEmpty())
			url = r.getFederationMember().getOpenidUrl().iterator().next();
		if (url != null && ! url.isEmpty())
		{
			sb.append(url);
			if (url.contains("?"))
				sb.append("&code=");
			else
				sb.append("?code=");
			sb.append( URLEncoder.encode(  token.authorizationCode) );
			if ( r.getState() != null)
				sb.append("&state=")
				.append( URLEncoder.encode(r.getState() , "UTF-8"));
			sb.append("&session_state=active");
			response.sendRedirect(sb.toString());
		} else {
			ServletOutputStream out = response.getOutputStream();
			response.setContentType("text/plain");
			out.println("Authorization code: "+token.authorizationCode);
			out.println("State: "+r.getState());
		}
		
	}
}
