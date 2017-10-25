package es.caib.seycon.idp.session;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;

import com.soffid.iam.service.SessionService;

import edu.internet2.middleware.shibboleth.idp.session.Session;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;

public class SessionManager {

    private static HashMap<Long, SessionInfo> sessionsBySeyconId = new HashMap<Long, SessionInfo>();
    private static HashMap<String, SessionInfo> sessionsByShibbolethId = new HashMap<String, SessionInfo>();
    
    
    public void registerSession (SessionInfo s) throws IOException, InternalErrorException, UnknownUserException {
        SessionService sessioService = getSessionService();
        String localHost = Config.getConfig().getHostName();
        
        IdpConfig idpConfig;
        try {
            idpConfig = IdpConfig.getConfig();
        } catch (Exception e) {
            throw new IOException(e);
        }
        String url = String.format ("https://%s:%d/SeyconSessionManager", idpConfig.getHostName(), idpConfig.getStandardPort()); //$NON-NLS-1$
        sessioService.registerWebSession(s.getUser(), localHost, s.getRemoteIp(), url);
        
        s.creation = new Date();
        s.lastUpdate = null;
        
        sessionsByShibbolethId.put(s.getIdpSession().getSessionID(), s);
        sessionsBySeyconId.put(s.getSessionId(), s);
    }

    private SessionService getSessionService() throws IOException, es.caib.seycon.ng.exception.InternalErrorException {
    	return ServerLocator.getInstance().getRemoteServiceLocator().getSessionService();
    }

    public void sessionKeepAlive (SessionInfo s) throws InternalErrorException, IOException, ExpiredSessionException {
        SessionService ss = getSessionService();
        com.soffid.iam.api.Session seyconSession = null;
        try {
            seyconSession = ss.getSession(s.getSessionId(), s.getSessionKey());
        } catch (InternalErrorException e) {
        }
        if (seyconSession == null) {
            removeSession(s);
            throw new ExpiredSessionException ();
        } else {
            getSessionService().sessionKeepAlive(seyconSession);
        }
    }

    public void removeSession (SessionInfo s) {
        try {
            SessionService ss = getSessionService();
            com.soffid.iam.api.Session seyconSession = ss.getSession(s.getSessionId(), s.getSessionKey());
            if (seyconSession != null )
                ss.destroySession(seyconSession);
        } catch (Exception e) {
            
        }
        sessionsByShibbolethId.remove(s.getIdpSession().getSessionID());
        sessionsBySeyconId.remove(s.getSessionId());
    }

    public SessionInfo getSessionByShibbolethId (Session s) {
        return sessionsByShibbolethId.get(s.getSessionID());
    }
}
