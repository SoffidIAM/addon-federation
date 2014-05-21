package es.caib.seycon.idp.session;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;

import edu.internet2.middleware.shibboleth.idp.session.Session;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.comu.Sessio;
import es.caib.seycon.ng.servei.SessioService;

public class SessionManager {

    private static HashMap<Long, SessionInfo> sessionsBySeyconId = new HashMap<Long, SessionInfo>();
    private static HashMap<String, SessionInfo> sessionsByShibbolethId = new HashMap<String, SessionInfo>();
    
    
    public void registerSession (SessionInfo s) throws IOException, InternalErrorException, UnknownUserException {
        SessioService sessioService = getSessionService();
        String localHost = Config.getConfig().getHostName();
        
        IdpConfig idpConfig;
        try {
            idpConfig = IdpConfig.getConfig();
        } catch (Exception e) {
            throw new IOException(e);
        }
        String url = String.format ("https://%s:%d/SeyconSessionManager", idpConfig.getHostName(), idpConfig.getStandardPort()); //$NON-NLS-1$
        sessioService.registraSessioWeb(s.getUser(), localHost, s.getRemoteIp(), url);
        
        s.creation = new Date();
        s.lastUpdate = null;
        
        sessionsByShibbolethId.put(s.getIdpSession().getSessionID(), s);
        sessionsBySeyconId.put(s.getSessionId(), s);
    }

    private SessioService getSessionService() throws IOException, es.caib.seycon.ng.exception.InternalErrorException {
    	return ServerLocator.getInstance().getRemoteServiceLocator().getSessioService();
    }

    public void sessionKeepAlive (SessionInfo s) throws InternalErrorException, IOException, ExpiredSessionException {
        SessioService ss = getSessionService();
        Sessio seyconSession = null;
        try {
            seyconSession = ss.getSession(s.getSessionId(), s.getSessionKey());
        } catch (InternalErrorException e) {
        }
        if (seyconSession == null) {
            removeSession(s);
            throw new ExpiredSessionException ();
        } else {
            getSessionService().sessioKeepAlive(seyconSession);
        }
    }

    public void removeSession (SessionInfo s) {
        try {
            SessioService ss = getSessionService();
            Sessio seyconSession = ss.getSession(s.getSessionId(), s.getSessionKey());
            if (seyconSession != null )
                ss.destroySessio(seyconSession);
        } catch (Exception e) {
            
        }
        sessionsByShibbolethId.remove(s.getIdpSession().getSessionID());
        sessionsBySeyconId.remove(s.getSessionId());
    }

    public SessionInfo getSessionByShibbolethId (Session s) {
        return sessionsByShibbolethId.get(s.getSessionID());
    }
}
