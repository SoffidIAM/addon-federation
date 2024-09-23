package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdpNetworkConfig;
import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.User;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.sync.service.QueryService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class QueryServlet extends HttpServlet {

    private QueryService queryService;
    public QueryServlet () {
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String path = req.getPathInfo();
        String nofail = req.getParameter("nofail");
        String user = req.getParameter("user");
        String sessionKey = req.getParameter("sessionKey");
        BufferedWriter writer = new BufferedWriter (new OutputStreamWriter(resp.getOutputStream(),"UTF-8"));
        try {
        	String r = builtinQuery(path);
        	if (r == null) {
        		if ( ! authorized (path, user, sessionKey))
            		writer.write( "ERROR|Unauthorized " );
        		else
        			writer.write( new RemoteServiceLocator().getEssoService().query(path, req.getRemoteAddr(), "text/plain"));
        	}
        	else 
        		writer.write("OK|2|CON_ORDRE|CON_VALOR|1|"+r);
        } catch (Exception e) {
            if (e.getMessage().equals ("not found") && nofail != null) {
                resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            else
            {
                log ("Error querying path "+path, e);
                resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                writer.write("ERROR|"+e.toString());
            }
        }
        writer.flush ();
    }

	private boolean authorized(String path, String user, String sessionKey) throws InternalErrorException, IOException {
		if (path.startsWith("/config/"))
			return true;
		
		User u = new RemoteServiceLocator().getUserService().findUserByUserName(user);
		if (u == null)
			return false;
        SessionService sessioService = new RemoteServiceLocator().getSessionService();
		for (Session session: sessioService.getActiveSessions(u.getId()))
        	if (session.getKey().equals(sessionKey))
        		return true;
		return false;
	}

	private String builtinQuery(String path) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
    	SAMLProfile profile = IdpConfig.getConfig().getEssoProfile();
    	FederationMember fm = IdpConfig.getConfig().getFederationMember();
		switch(path) {
		case "/config/soffid.hostname.format":
			return profile.getHostnameFormat();
		case "/config/soffid.esso.protocol":
			return "2";
		case "/config/SSOServer":
			return fm.getHostName();
		case "/config/QueryServer":
			return fm.getHostName();
		case "/config/seycon.https.port":
			for (IdpNetworkConfig cfg: fm.getNetworkConfig())
				return Integer.toString( cfg.isProxy() ? cfg.getProxyPort() : cfg.getPort() );
			return "443";
		case "/config/SSOSoffidAgent":
			return profile.getMainAgent();
		case "/config/EnableCloseSession":
			return profile.getEnableCloseSession() == null ? "false": profile.getEnableCloseSession().toString();
		case "/config/ForceStartupLogin":
			return profile.getForceStartupLogin() == null ? "false": profile.getForceStartupLogin().toString();
		case "/config/soffid.esso.session.keepalive":
			return Integer.toString( profile.getKeepAlive() );
		case "/config/soffid.esso.idleTimeout":
			return Integer.toString( profile.getIdleTimeout() );
		case "/config/soffid.esso.sharedWorkstation":
			return profile.getSharedWorkstation() == null ? "false": profile.getSharedWorkstation().toString();
		case "/config/SSOCredentialProvider":
			return profile.getWindowsCredentialProvider() == null ? "false": profile.getWindowsCredentialProvider().toString();
		case "/config/SSOCreateLocalAccounts":
			return profile.getCreateLocalAccounts() == null? "false": profile.getCreateLocalAccounts().toString();
		case "/config/SSOShowPreviousUser":
			return profile.getShowPreviousUser() == null ? "false": profile.getShowPreviousUser().toString();
		case "/config/SSOOfflineDetector":
			return profile.getOfflineDetector() == null ? "false": profile.getOfflineDetector().toString();
		case "/config/SSOOfflineDays":
			return profile.getOfflineDays() == null ? null: profile.getOfflineDays().toString();
		default:
			return null;
		}
	}
}