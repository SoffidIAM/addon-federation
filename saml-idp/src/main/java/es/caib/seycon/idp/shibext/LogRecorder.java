package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.common.session.Session;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.sync.intf.LogEntry;

public class LogRecorder {

    private static LogRecorder instance;
    IdpConfig config;

    private LogRecorder() {
    	try {
			config = IdpConfig.getConfig();
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

    List<LogEntry> logs =  Collections.synchronizedList(new LinkedList<LogEntry>());
    Map<String,List<LogEntry>> activeLogs = new Hashtable<String, List<LogEntry>>(); // Soffid session -> SP sessions
	static Map<String, HttpSession> shibbolethToHttpSessions = new Hashtable<>(); // Shibboleth session -> Soffid session

    public static LogRecorder getInstance() {
        if (instance == null)
            instance = new LogRecorder();
        return instance;
    }

    /**
     * Returns the logout entry point
     * 
     * @param type
     * @param user
     * @param authMethod
     * @param serviceProvider
     * @param remoteIp
     * @param session
     * @param shibbolethSession
     * @return
     * @throws IOException
     */
    public synchronized LogEntry addSuccessLogEntry(String type, String user, String authMethod, String serviceProvider,
            String remoteIp, HttpSession session, Session shibbolethSession, String tokenId) throws IOException {
        LogEntry le = new LogEntry();
        le.setClient(remoteIp);
        try {
            le.setHost(IdpConfig.getConfig().getHostName());
        } catch (Exception e) {
            throw new IOException("Unable to get configuration"); //$NON-NLS-1$
        }
        
        final String prefix = "urn:oasis:names:tc:SAML:2.0:ac:classes:";
        if (authMethod.startsWith(prefix))
        	authMethod = authMethod.substring(prefix.length());
        
        le.info = String.format("Auth method: %s", authMethod); //$NON-NLS-1$
        le.setHost(serviceProvider);
        le.setClient(remoteIp);
        le.setProtocol(type); //$NON-NLS-1$
        le.setDate(new Date());
        le.SessionId = le.getHost() + "-" + System.currentTimeMillis(); //$NON-NLS-1$
        le.type = LogEntry.LOGON;
        le.setUser(user);
        logs.add(le);
        
        LogEntry le2 = new LogEntry();
        le2.info = String.format("Auth method: %s", authMethod); //$NON-NLS-1$
        le2.setHost(serviceProvider);
        le2.setClient(remoteIp);
        le2.setProtocol(type); //$NON-NLS-1$
        le2.setDate(new Date());
        le2.SessionId = le.getHost() + "-" + System.currentTimeMillis(); //$NON-NLS-1$
        le2.type = LogEntry.LOGOFF;
        le2.setUser(user);
        
        if (tokenId == null) tokenId = session.getId();
		List<LogEntry> entries = activeLogs.get(tokenId);
		if ( entries == null )
		{
			entries = new LinkedList<>();
			activeLogs.put (tokenId, entries);			
		}
		entries.add(le2);
		if (shibbolethSession != null && shibbolethSession.getSessionID() != null) {
			shibbolethToHttpSessions.put(shibbolethSession.getSessionID(), session);
		}
		return le2;
    }

    public synchronized void flushLogoutEntry(String tokenId) {
		List<LogEntry> le = activeLogs.get(tokenId);
		if (le != null)
		{
			for (LogEntry log: le) {
				log.setDate(new Date());
				logs.add(log);
			}
			activeLogs.remove(tokenId);
		}
    }
    
    public synchronized void keepAliveLogSession(HttpSession session) throws IOException {
    	if (session != null)
    	{
    		List<LogEntry> le = activeLogs.get(session.getId());
			if (le != null)
    			for (LogEntry log: le)
    				log.setDate(new Date());
    	}
    }

    public synchronized void closeSession (HttpSession session) 
    {
    	if (session != null)
    	{
	        edu.internet2.middleware.shibboleth.idp.session.Session shibbolethSession = 
	        		(edu.internet2.middleware.shibboleth.idp.session.Session)
	        			session.getAttribute(edu.internet2.middleware.shibboleth.idp.session.Session.HTTP_SESSION_BINDING_ATTRIBUTE);
	        if (shibbolethSession != null)
	        	shibbolethToHttpSessions.remove(shibbolethSession.getSessionID());
    		List<LogEntry> le = activeLogs.get(session.getId());
    		if (le != null)
    		{
    			for (LogEntry log: le) {
    				log.setDate(new Date());
    				logs.add(log);
    			}
    			activeLogs.remove(session.getId());
    		}
    	}
    }

    public synchronized void closeSession (edu.internet2.middleware.shibboleth.idp.session.Session session) 
    {
    	if (session != null)
    	{
    		HttpSession httpSession =  shibbolethToHttpSessions.get(session.getSessionID());
    		if (httpSession != null)
    			closeSession(httpSession);
    	}
    }

    public synchronized void addErrorLogEntry(String user, String info, String remoteIp)
            throws IOException {
        LogEntry le = new LogEntry();
        le.setClient(remoteIp);
        try {
            le.setHost(IdpConfig.getConfig().getHostName());
        } catch (Exception e) {
            throw new IOException("Unable to get configuration"); //$NON-NLS-1$
        }
        le.info = info;
        le.setHost(config.getHostName());
        le.setClient(remoteIp);
        le.setProtocol("SAML"); //$NON-NLS-1$
        le.setDate(new Date());
        le.SessionId = le.getHost() + "-" + System.currentTimeMillis(); //$NON-NLS-1$
        le.type = 2;
        le.setUser(user);
        logs.add(le);
    }

    public synchronized Collection<es.caib.seycon.ng.sync.intf.LogEntry> getLogs(Date d) {
        List<LogEntry> l = new LinkedList<LogEntry>();
        for (java.util.Iterator<LogEntry> it = logs.iterator(); it.hasNext() && l.size() < 1000;) {
        	LogEntry log = it.next();
        	if (d == null || log.getDate().after(d))
        	{
        		l.add(log);
        	} else {
        		it.remove();
        	}
        }
        return logs;
    }
}

