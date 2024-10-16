package es.caib.seycon.idp.cas;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.openid.server.TokenHandler;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.server.AuthorizationHandler;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class LoginResponse  {
	static Log log = LogFactory.getLog(LoginResponse.class);
	
	public static void generateResponse (ServletContext ctx, HttpServletRequest request, HttpServletResponse response, String authType, String sessionHash) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException
	{
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		log.info("Generating openid response");
		if (!checkAuthorization(user, r, request, response)) {
			log.info("Not authorized to login");
			unauthorized(request, response, r, user);
		} else {
			log.info("Returnig authorization flow");
			authorizationFlow (request, response, authType, sessionHash);			
		}
	}

	private static void unauthorized(HttpServletRequest request, HttpServletResponse response, OpenIdRequest r, String user) throws UnsupportedEncodingException, IOException, ServletException {
		throw new ServletException("Access denied for user "+user);
	}

	private static boolean checkAuthorization(String user, OpenIdRequest r, HttpServletRequest request, HttpServletResponse response) throws InternalErrorException, UnknownUserException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		AuthenticationContext authCtx = AuthenticationContext.fromRequest(request);
    	return new AuthorizationHandler().checkAuthorization(user, r.getFederationMember(),
				authCtx == null ? null: authCtx.getHostId(response),
				request.getRemoteAddr());
	}

	private static void authorizationFlow(HttpServletRequest request, HttpServletResponse response, String authType, String sessionHash) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, ServletException {
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		TokenHandler h = TokenHandler.instance();
		TokenInfo token = h.generateAuthenticationRequest(r, user, authType, new Autenticator().getSession(request, true), sessionHash);

		Map<String, Object> att;
		try {
			att = new UserAttributesGenerator().generateAttributes(request.getServletContext(), token);
		} catch (Exception e) {
			log.warn("Error generating response", e);
			throw new ServletException("Error resolving attributes", e);
		}

		h.generateToken(token, att, request, authType);
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
				sb.append("&ticket=");
			else
				sb.append("?ticket=");
			sb.append( URLEncoder.encode(  token.getToken() , StandardCharsets.UTF_8.name()) );
			response.sendRedirect(sb.toString());
		} else {
			ServletOutputStream out = response.getOutputStream();
			response.setContentType("text/plain");
			out.println("CAS Ticket: "+token.getAuthenticationMethod());
		}
		
	}
}
