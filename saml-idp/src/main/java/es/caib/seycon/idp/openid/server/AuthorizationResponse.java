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
	
	public static void generateResponse (ServletContext ctx, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException
	{
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		if ( "code".equals(r.getResponseType()))
			authorizationFlow (request, response);
		else if ("id_token".equals(r.getResponseType()) || 
			"id_token token".equals(r.getResponseType() ))
			implicitFLow (ctx, request, response);
		else
			throw new ServletException ("Unexpecte response type "+r.getResponseType());
		

	}

	private static void implicitFLow(ServletContext ctx, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		TokenHandler h = TokenHandler.instance();
		TokenInfo token = h.generateAuthenticationRequest(r, user);
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
				sb.append(url)
					.append("?access_token=")
					.append( URLEncoder.encode(  token.authorizationCode) )
					.append("&token_type=bearer")
					.append("&id_token=")
					.append( URLEncoder.encode(openidToken , "UTF-8"))
					.append("&expires_in=")
					.append ( (token.expires - System.currentTimeMillis()) / 1000);
				if ( r.getState() != null)
					sb.append("&state=")
					.append( URLEncoder.encode(r.getState() , "UTF-8"));
				response.sendRedirect(sb.toString());
			} else {
				ServletOutputStream out = response.getOutputStream();
				response.setContentType("text/plain");
				out.println("Authorization code: "+token.authorizationCode);
				out.println("State: "+r.getState());
			}
			
		} catch (AttributeResolutionException e) {
			log.warn("Error resolving attributes", e);
			buildError(response, "Error resolving attributes");
			return;
		} catch (AttributeFilteringException e) {
			log.warn("Error filtering attributes", e);
			buildError(response, "Error resolving attributes");
			return;
		} catch (InternalErrorException e) {
			log.warn("Error evaluating claims", e);
			buildError(response, "Error resolving attributes");
			return;
		} catch (JSONException e) {
			log.warn("Error generating response", e);
			buildError(response, "Error generating response");
			return;
		} catch (Throwable e) {
			log.warn("Error generating open id token", e);
			buildError(response, "Error generating open id token");
			return;
		}


		
	}

	private static void buildError(HttpServletResponse resp, String string) throws IOException, ServletException {
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

	private static void authorizationFlow(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);

		TokenHandler h = TokenHandler.instance();
		TokenInfo token = h.generateAuthenticationRequest(r, user);
		
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
			response.sendRedirect(sb.toString());
		} else {
			ServletOutputStream out = response.getOutputStream();
			response.setContentType("text/plain");
			out.println("Authorization code: "+token.authorizationCode);
			out.println("State: "+r.getState());
		}
		
	}
}
