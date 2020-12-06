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
import org.json.JSONObject;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;

public class AuthorizationResponse  {
	static Log log = LogFactory.getLog(AuthorizationResponse.class);
	
	public static void generateResponse (ServletContext ctx, HttpServletRequest request, HttpServletResponse response, String authType) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException
	{
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		if ( r.getResponseTypeSet().contains("code"))
			authorizationFlow (request, response, authType);
		else
			implicitFLow (ctx, request, response, authType);
	}

	private static void implicitFLow(ServletContext ctx, HttpServletRequest request, HttpServletResponse response, String authType) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		TokenHandler h = TokenHandler.instance();
		TokenInfo token = h.generateAuthenticationRequest(r, user, authType);
		String authenticationMethod = (String) s.getAttribute(SessionConstants.AUTHENTICATION_USED);
		token.setAuthenticationMethod(authenticationMethod);
		h.generateToken (token);
		
		Map<String, Object>att  ;
		try {
			att = new UserAttributesGenerator().generateAttributes ( ctx, token );
			String openidToken = h.generateIdToken (token, att);
			StringBuffer sb = new StringBuffer();
			String url = r.getFederationMember().getOpenidUrl();
			if (url == null || url.isEmpty())
				url = r.getRedirectUrl();
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
				boolean first = true;
				sb.append(url);
				for ( String arg: args)
				{
					if (first) sb.append('?');
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
		resp.sendRedirect(r.getRedirectUrl()+"?error=server_error&error_description="+
				URLEncoder.encode(description, "UTF-8")+
				(r.getState() != null ? "&state="+r.getState(): ""));
	}

	private static void authorizationFlow(HttpServletRequest request, HttpServletResponse response, String authType) throws IOException, InternalErrorException {
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		TokenHandler h = TokenHandler.instance();
		TokenInfo token = h.generateAuthenticationRequest(r, user, authType);
		String authenticationMethod = (String) s.getAttribute(SessionConstants.AUTHENTICATION_USED);
		token.setAuthenticationMethod(authenticationMethod);
		
		StringBuffer sb = new StringBuffer();
		String url = r.getFederationMember().getOpenidUrl();
		if (url == null || url.isEmpty())
			url = r.getRedirectUrl();
		if (url != null && ! url.isEmpty())
		{
			sb.append(url)
			.append("?code=")
			.append( URLEncoder.encode(  token.authorizationCode) );
			if ( r.getState() != null)
				sb.append("&state=")
				.append( URLEncoder.encode(r.getState() , "UTF-8"));
			if ( r.getNonce() != null)
				sb.append("&nonce=")
				.append( URLEncoder.encode(r.getNonce() , "UTF-8"));
			response.sendRedirect(sb.toString());
		} else {
			ServletOutputStream out = response.getOutputStream();
			response.setContentType("text/plain");
			out.println("Authorization code: "+token.authorizationCode);
			out.println("State: "+r.getState());
		}
		
	}
}
