package es.caib.seycon.idp.openid.server;

import java.io.IOException;
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
import java.util.HashMap;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.AllowedScope;
import com.soffid.iam.api.Group;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class AuthorizationEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	static HashMap<String, Long> lastSectorUpdate = new HashMap<>();
	
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		IdpConfig config;
		OpenIdRequest r;
		try {
			config = IdpConfig.getConfig();
			req.getSession().setAttribute("soffid-session-type", "openid");
			String hgSession = (String) req.getSession().getAttribute(SessionConstants.OPENID_HOLDERGROUP);

	    	r = new OpenIdRequest();
	    	r.setScope(getScopeFromRequest(req));
	    	r.setClientId(req.getParameter("client_id"));
	    	r.setResponseType(req.getParameter("response_type"));
	    	r.setState(req.getParameter("state"));
	    	r.setNonce(req.getParameter("nonce"));
	    	r.setFederationMember( config.getFederationService().findFederationMemberByClientID(r.getClientId()) );
	    	r.setRedirectUrl(req.getParameter("redirect_uri"));
	    	r.setPkceAlgorithm(req.getParameter("code_challenge_method"));
	    	r.setPkceChallenge(req.getParameter("code_challenge"));
	    	r.setLoginHint(req.getParameter("login_hint"));
	    	r.setHolderGroup(getHolderGroupFromScopeAndSession(r.getScope(), hgSession));
	    	if (r.getFederationMember() != null && r.getRedirectUrl() == null) {
	    		if (r.getFederationMember().getOpenidUrl() != null && !r.getFederationMember().getOpenidUrl().isEmpty())
	    		r.setRedirectUrl(r.getFederationMember().getOpenidUrl().iterator().next());
	    	}
	    	if (OidcDebugController.isDebug()) {
				log.info("Received authorization request:");
				log.info("client_id      = "+r.getClientId());
				log.info("response_type  = "+r.getResponseType());
				log.info("state          = "+r.getState());
				log.info("nonce          = "+r.getNonce());
				log.info("redirect_uri   = "+r.getRedirectUrl());
				log.info("scope          = "+r.getScope());
				log.info("code_algorithm = "+r.getPkceAlgorithm());
				log.info("code_challenge = "+r.getPkceChallenge());
				log.info("login_hint     = "+r.getLoginHint());
				log.info("holderGroup    = "+r.getHolderGroup());
	    	}

	    	// Check if the holderGroup is present in session and in the scope,
	    	// and if there is different a logout is requiered to continue.
	    	// URI in base64 as an internal redirect
	    	if (r.getHolderGroup()!=null && hgSession!=null && !r.getHolderGroup().equals(hgSession)) {
	    		String uri = "";
	    		for (String p : req.getParameterMap().keySet())
	    			uri = uri+(uri.isEmpty() ? "?" : "&")+p+"="+req.getParameter(p);
	    		uri = req.getRequestURI()+uri;
	    		uri = "BASE64"+Base64.getEncoder().encodeToString(uri.getBytes());
	    		String finalURL = "logout?client_id="+r.getClientId()+"&post_logout_redirect_uri="+uri;
	    		log.info(">>> HOLDERGROUP - Detected HolderGroup change (session="+hgSession+", scope="+r.getHolderGroup()+"), redirection to logout: "+finalURL);
	    		resp.sendRedirect(finalURL);
	    		return;
	    	}

	    	HttpSession session = req.getSession(true);
	    	if (r.getFederationMember() != null) {
		    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
	        	session.setAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM, null);
	    	}	    	
		} catch (Exception e) {
			throw new ServletException("Error parsing request paramenters", e);
		}
    	
    	if ( ! checkParameters (r, resp))
    		return;
    	
    	try {
	    	if ( ! r.getFederationMember().getOpenidMechanism().contains( "IM" ) && 
	    		  r.getResponseType().contains("token"))
	    	{
	    		throw new ServletException("Not authorized to use implicit flow, requested response: "+r.getResponseType());
	    	}
	    	if ( ! r.getFederationMember().getOpenidMechanism().contains( "AC" ) && 
		    		  r.getResponseType().contains("code"))
	    	{
	    		throw new ServletException("Not authorized to use athorization code flow, requested response: "+r.getResponseType());
	    	}
	    	HttpSession session = req.getSession();
	    	session.setAttribute(SessionConstants.OPENID_REQUEST, r);
	    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());

	    	if (r.getHolderGroup()!=null)
	    		session.setAttribute(SessionConstants.OPENID_HOLDERGROUP, r.getHolderGroup());

    		clientCredentialsGrantType(req, resp);
	    	
    	} catch (Exception e) {
            generateError(r, "server_error", e.toString(), resp);
		}
	}

	private String getScopeFromRequest(HttpServletRequest req) {
		String[] a = req.getParameterValues("scope");
		if (a!=null && a.length>0) {
			HashMap<String, String> hm = new HashMap<String, String>();
			for (String i : a) {
				for (String i2 : i.split(" ")) {
					hm.put(i2.trim(), i2.trim());
				}
			}
			String o = "";
			for (String i : hm.keySet()) {
				if (!i.trim().isEmpty()) {
					if (o.length()>0)
						o = o+" ";
					o = o+i;
				}
			}
			return o;
		}
		return null;
	}

	private String getHolderGroupFromScopeAndSession(String scope, String sessionHolderGroup) {
		if (scope==null || !scope.toLowerCase().contains("holdergroup:"))
			return getHolderGroupFromSession(sessionHolderGroup);

		String[] sa = scope.trim().split(" ");
		for (String s : sa) {
			if (s.toLowerCase().startsWith("holdergroup:")) {
				String hg = s.substring(s.indexOf(":")+1);
				if (hg!=null && !hg.trim().isEmpty()) {
					try {
						hg =  URLDecoder.decode(hg,"UTF-8");
						Group g = new RemoteServiceLocator().getGroupService().findGroupByGroupName(hg);
						if (g!=null)
							return g.getName();
					} catch (InternalErrorException | IOException e) {}
				}
				return getHolderGroupFromSession(sessionHolderGroup);
			}
		}
		return getHolderGroupFromSession(sessionHolderGroup);
	}

	private String getHolderGroupFromSession(String sessionHolderGroup) {
		if (sessionHolderGroup!=null) {
			try {
				Group g = new RemoteServiceLocator().getGroupService().findGroupByGroupName(sessionHolderGroup);
				if (g!=null)
					return g.getName();
			} catch (InternalErrorException | IOException e) {}
		}
		return null;
	}

	private void clientCredentialsGrantType(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException {
		String user = (String) req.getSession().getAttribute(SessionConstants.SEU_USER);
		if ("none".equals(req.getParameter("prompt")) && user != null) {
			AuthorizationResponse.generateResponse(getServletContext(), req, resp, "P", null);
			return;
		} 
		RequestDispatcher dispatcher = req.getRequestDispatcher(LoginServlet.URI);
		dispatcher.forward(req, resp);
	}


	private void generateError(OpenIdRequest r, String error, String description, HttpServletResponse resp) throws IOException {
		if (OidcDebugController.isDebug()) {
			log.info("Sending back error "+error+": "+description);
		}
		resp.sendRedirect(r.getRedirectUrl()+ (r.getRedirectUrl().contains("?") ? "&": "?") + "error="+error+"&error_description="+
				URLEncoder.encode(description, "UTF-8")+
				(r.getState() != null ? "&state="+r.getState(): ""));
	}

	private boolean checkParameters(OpenIdRequest r, HttpServletResponse resp) throws ServletException, IOException {
    	boolean found  = false;
    	if (r.getScope() != null) {
	    	for (String s: r.getScope().split(" +"))
	    	{
	    		if (s.equalsIgnoreCase("openid")) found = true;
	    	}
    	} else {
    		found = true;
    	}

    	if (! found)
    	{
            generateError(r, "invalid_scope", "The requested scope does not contain the scope openid: "+r.getScope(), resp);
            return false;
    	}
		
    	if (r.getFederationMember() == null)
    	{
            generateError(r, "unauthorized_client", "Unknown client id "+r.getClientId(), resp);
            return false;
    	}
    	
    	if (r.getScope() != null) {
	    	for (String s: r.getScope().split(" +")) {
	    		found = false;
	    		for (AllowedScope scope: r.getFederationMember().getAllowedScopes()) {
	    			if (scope.getScope().equals("*") || scope.getScope().equals(s)) {
	    				found = true; 
	    				break;
	    			}
	    		}
        		if (s.startsWith("holdergroup:")) {
        			found = true;
        		}
		    	if (!found) {
		    		generateError(r, "invalid_scope", "The requested scope "+s+" is not allowed due to system policies", resp);
		    		return false;
		    	}
	    	}
    	}
    	if (r.getResponseType() == null)
    	{
            generateError(r, "unsupported_response_type", "Wrong value for response_type: "+r.getResponseType(), resp);
            return false;
    	}
    	
    	if ( ! "code".equals( r.getResponseType()) && 
    			! "token".equals(r.getResponseType()) &&
    			! "id_token".equals(r.getResponseType()) &&
    			! "id_token token".equals(r.getResponseType()) &&
    			! "code id_token".equals(r.getResponseType()) &&
    			! "code token".equals(r.getResponseType()) &&
    			! "code id_token token".equals(r.getResponseType())
    			)
    	{
            generateError(r, "unsupported_response_type", "Wrong value for response_type: "+r.getResponseType(), resp);
            return false;
    	}


    	if (r.getRedirectUrl() == null)
    	{
            generateError(r, "invalid_request", "Missing redirect_uri", resp);
            return false;
    	}
    	if (r.getFederationMember().getOpenidSectorIdentifierUrl() != null &&
    			! r.getFederationMember().getOpenidSectorIdentifierUrl().trim().isEmpty()) {
    		Long last = lastSectorUpdate.get(r.getFederationMember().getPublicId());
    		if (last == null || last.longValue() < System.currentTimeMillis() - 900_000 ||  !isReturnUrlValid(r)) { // 15 minutes
    			try {
					r.setFederationMember(IdpConfig.getConfig().getFederationService().updateSectorIdentifier(r.getFederationMember()));
					lastSectorUpdate.put(r.getFederationMember().getPublicId(), System.currentTimeMillis());
				} catch (UnrecoverableKeyException | InvalidKeyException | KeyStoreException | NoSuchAlgorithmException
						| CertificateException | IllegalStateException | NoSuchProviderException | SignatureException
						| InternalErrorException | IOException e) {
					// Ignore temporary server error
				}
    		}
    	}
    	boolean ok = isReturnUrlValid(r);
    	if (!ok) {
    		generateError(r, "invalid_request", "The requested return URL is not accepted "+r.getRedirectUrl(), resp);
    		return false;
    	}
    	
    	Set<String> mechs = r.getFederationMember().getOpenidMechanism();
    	if (! mechs.contains("IM") && ! mechs.contains("AC"))
    	{
            generateError(r, "unauthorized_client", "Client must use token endpoint with password grant_type", resp);
            return false;
    	}
    	return true;
	}

	private boolean isReturnUrlValid(OpenIdRequest r) {
		boolean ok = false;
    	for (String url: r.getFederationMember().getOpenidUrl()) {
    		if (r.getRedirectUrl().equals(url) || r.getRedirectUrl().startsWith(url+"?")) 
    			ok = true;
    		if (url.endsWith("*") && r.getRedirectUrl().startsWith(url.substring(0, url.length()-1))) 
    			ok = true;
    	}
		return ok;
	}
}
