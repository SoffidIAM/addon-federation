package es.caib.seycon.idp.wsfed;

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

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthorizationHandler;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class WsfedResponse  {
	static Log log = LogFactory.getLog(WsfedResponse.class);
	
	public static void generateResponse (ServletContext ctx, HttpServletRequest request, HttpServletResponse response, String authType, String sessionHash) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException
	{
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		WsfedRequest r = (WsfedRequest) s.getAttribute(SessionConstants.WSFED_REQUEST);

		log.info("Generating openid response");
		if (!checkAuthorization(user, r)) {
			log.info("Not authorized to login");
			unauthorized(request, response, r, user);
		} else  {
			log.info("Returnig authorization flow");
			wsfedFLow (request, response, authType, sessionHash);			
		}
	}

	private static void unauthorized(HttpServletRequest request, HttpServletResponse response, 
			WsfedRequest r, String user) throws UnsupportedEncodingException, IOException, ServletException {
		throw new ServletException("Access denied fo user "+user);
	}

	private static boolean checkAuthorization(String user, OpenIdRequest r) throws InternalErrorException, UnknownUserException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		FederationService fs = new RemoteServiceLocator().getFederacioService();
    	FederationMember member = fs.findFederationMemberByClientID(r.getClientId());
    	return new AuthorizationHandler().checkAuthorization(user, member);
	}

	private static void wsfedFlow(ServletContext ctx, HttpServletRequest request, HttpServletResponse response, 
			String authType, String sessionHash) throws IOException, ServletException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		HttpSession s = request.getSession();
		String user = (String) s.getAttribute(SessionConstants.SEU_USER);
		WsfedRequest r = (WsfedRequest) s.getAttribute(SessionConstants.WSFED_REQUEST);

		Map<String, Object> att;
		try {
			TokenInfo t = new TokenInfo();
			t.setAuthentication(System.currentTimeMillis());
			t.setAuthenticationMethod(authType);
			t.setCreated(System.currentTimeMillis());
			t.setExpires(System.currentTimeMillis());
			t.setUser(user);
			final OpenIdRequest oidr = new OpenIdRequest();
			t.setRequest(oidr);
			oidr.setFederationMember(r.getFederationMember());

			att = new UserAttributesGenerator().generateAttributes(ctx, t, false, false, true);
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

		try {
			String response = generateResponse(r, user, att);
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

	private static String generateResponse(WsfedRequest r, String user, Map<String, Object> att) {
		return null;
	}

	private static void buildError(HttpServletResponse resp, WsfedRequest r, String description) throws IOException, ServletException {
		log.info("Internal error:"+description);
		throw new ServletException(description);
	}

}
