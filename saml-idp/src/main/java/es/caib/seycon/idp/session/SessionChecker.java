package es.caib.seycon.idp.session;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Map.Entry;
import java.util.Random;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.JSONObject;
import org.opensaml.xml.io.UnmarshallingException;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.ui.LogoutServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;

public class SessionChecker {
	private static final String ATTRIBUTE_NAME = "$soffid$session-tracker";
	private static final String COOKIE_NAME = "_session_checker";

	public void registerSession(HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, UnmarshallingException {
		HttpSession session = req.getSession();
        String relyingParty = (String) session.
                getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        if (relyingParty != null) {
        	String state = getSessionState(req);
        	byte b[] = new byte[16];
        	new Random().nextBytes(b);
        	String id = Base64.getEncoder().encodeToString(b);
        	session.setAttribute(ATTRIBUTE_NAME, id);
        	String c = URLEncoder.encode(id, "UTF-8")+"&"+
        			URLEncoder.encode(relyingParty, "UTF-8")+"&"+
        			URLEncoder.encode(state == null ? "": state, "UTF-8");
        	
        	final Cookie cookie = new Cookie(COOKIE_NAME, c);
        	cookie.setPath("/");
			resp.addCookie(cookie);
        }
	}
	
    public String getSessionState(HttpServletRequest req) throws UnmarshallingException {
    	final HttpSession session = req.getSession();
        if ("saml".equals(session.getAttribute("soffid-session-type")))
        {
			Saml2LoginContext saml2LoginContext = (Saml2LoginContext)HttpServletHelper.getLoginContext(req);
			if (saml2LoginContext == null) 
				saml2LoginContext = (Saml2LoginContext) session.getAttribute("$$soffid-old-login-context$$");
			if (saml2LoginContext != null && saml2LoginContext.getAuthenticiationRequestXmlObject() != null)
				return saml2LoginContext.getAuthenticiationRequestXmlObject().getID();
        } 
        else if ("openid".equals(session.getAttribute("soffid-session-type")))
        {
    		OpenIdRequest r = (OpenIdRequest) session.getAttribute(SessionConstants.OPENID_REQUEST);
    		if (r != null)
    			return r.getState();
        }
        return null;
	}

    public boolean checkSession(HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException {
		HttpSession session = req.getSession();
		for (Cookie c: req.getCookies()) {
			if (c.getName().equals(COOKIE_NAME)) {
				String parts[] = c.getValue().split("&");
				if (parts.length >= 2 && 
					URLDecoder.decode(parts[0],"UTF-8").equals(session.getAttribute(ATTRIBUTE_NAME)))
					return true;
			}
		}
		return false;
    }

    public void generateErrorPage(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		for (Cookie c: req.getCookies()) {
			if (c.getName().equals(COOKIE_NAME)) {
				String parts[] = c.getValue().split("&");
				try {
					generateLogoutPage(req, resp, 
							URLDecoder.decode(parts[1],"UTF-8"), 
							parts.length == 2 ? "": URLDecoder.decode(parts[2], "UTF-8"));
					return;
				} catch (Exception e) {
					throw new IOException("Error generating logout page", e);
				}
			}
		}
		resp.sendRedirect(LogoutServlet.URI);
    }

	public void generateLogoutPage(HttpServletRequest req, HttpServletResponse resp, String relyingParty, String state) throws IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		IdpConfig config = IdpConfig.getConfig();
		FederationMember idp = config.findIdentityProviderForRelyingParty(relyingParty);
		FederationMember sp = config.getFederationService().findFederationMemberByPublicId(relyingParty);
		if (idp == null || sp == null) {
			resp.sendRedirect(LogoutServlet.URI);
			return;
		}
		SamlRequest samlRequest = ((FederationService) new RemoteServiceLocator()
				.getRemoteService(FederationService.REMOTE_PATH))
				.generateErrorResponse(idp.getPublicId(), relyingParty, state);
		if (samlRequest.getMethod().equals( "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") )
		{
			resp.setContentType("text/html; charset=UTF-8");
			StringBuffer sb = new StringBuffer();
			sb.append("<html><body onLoad='document.forms[0].submit();'><form method='post' action='")
				.append(encodeXML(samlRequest.getUrl()))
				.append("'>");
			for (Entry<String, String> entry: samlRequest.getParameters().entrySet()) {
				sb.append("<input name='")
				  .append(entry.getKey())
				  .append("' type='hidden' value='")
				  .append(encodeXML(entry.getValue()))
				  .append("'/>");
			}
			sb.append("<input type='submit' value='Please, wait a second ....'/>")
				.append("</form>")
				.append("</body></html>");
			ServletOutputStream out = resp.getOutputStream();
			out.write(sb.toString().getBytes("UTF-8"));
			out.close();
		}
		else
		{
			resp.setContentType("text/html; charset=UTF-8");
			StringBuffer sb = new StringBuffer();
			sb.append(samlRequest.getUrl());
			for (Entry<String, String> entry: samlRequest.getParameters().entrySet()) {
				if (sb.toString().contains("?"))
					sb.append("&");
				else
					sb.append("?");
				sb.append(entry.getKey());
				sb.append("=");
				sb.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
			}
			resp.sendRedirect(sb.toString());
		}
	}
	
	private String encodeXML(String url) {
		return url.replace("\"", "\\\"").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
	}

}

