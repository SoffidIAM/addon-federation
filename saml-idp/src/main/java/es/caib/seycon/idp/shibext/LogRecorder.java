package es.caib.seycon.idp.shibext;

import java.io.FileNotFoundException;
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.api.Host;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.common.session.Session;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.LogEntry;

public class LogRecorder {

    private static LogRecorder instance;
    IdpConfig config;
    Log logger = LogFactory.getLog("idplog");

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
     * @throws InternalErrorException 
     */
    public synchronized LogEntry addSuccessLogEntry(String type, String user, String authMethod, 
    		String serviceProvider, String remoteHostName,
            String remoteIp, HttpSession session, Session shibbolethSession, String tokenId) throws IOException, InternalErrorException {
        LogEntry le = new LogEntry();

        if (remoteHostName != null) {
        	Host host = new RemoteServiceLocator().getUserBehaviorService().findHostBySerialNumber(remoteHostName);
        	if (host != null)
        		remoteHostName = host.getName();
        }
        
        logger.info("LOGON "+user+"|"+remoteIp+"|"+serviceProvider+"|"+type+"|"+authMethod);
        if (isNewVersion() && remoteIp != null && remoteHostName != null) {
        	remoteIp = remoteHostName+" "+remoteIp;
        } else if (remoteHostName != null){
        	remoteIp = remoteHostName;
        }
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
        le.SessionId = le.getProtocol()+"-"+le.getHost() + "-" + System.currentTimeMillis(); //$NON-NLS-1$
        le.type = LogEntry.LOGON;
        le.setUser(user);
        logs.add(le);
        
        LogEntry le2 = new LogEntry();
        le2.info = String.format("Auth method: %s", authMethod); //$NON-NLS-1$
        le2.setHost(serviceProvider);
        le2.setClient(remoteIp);
        le2.setProtocol(type); //$NON-NLS-1$
        le2.setDate(new Date());
        le2.SessionId = le.getProtocol()+"-"+le.getHost() + "-" + System.currentTimeMillis(); //$NON-NLS-1$
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

    String version = null;
    private boolean isNewVersion() throws FileNotFoundException, IOException {
    	try {
    		if (version == null)
    			version = Config.getConfig().getVersion();
	        String[] split = version.split("[-.]");
	        if ( Integer.parseInt(split[0]) > 3) return true;
	        if ( Integer.parseInt(split[0]) < 3) return false;
	        if ( Integer.parseInt(split[1]) > 5) return true;
	        if ( Integer.parseInt(split[1]) < 5) return false;
	        return Integer.parseInt(split[2]) >= 10;
    	} catch (NumberFormatException e) {
    		return false;
    	}
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
    				String host = log.getHost();
    				if (host.contains(" "))
    					host = host.substring(host.lastIndexOf(" ")+1);
    				logger.info("LOGOFF "+log.user+"|"+log.getClient()+"|"+log.getHost()+"|"+log.getProtocol());
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

    public synchronized void addErrorLogEntry(String protocol,
    		String user, String info, 
    		String serviceProvider,
    		String remoteHostName, String remoteIp)
            throws IOException, InternalErrorException {
        LogEntry le = new LogEntry();
        logger.info("LOGON-DENIED "+user+"|"+remoteIp+"|"+serviceProvider+"|"+protocol);
        if (isNewVersion() && remoteHostName != null) {
        	Host h = new RemoteServiceLocator().getUserBehaviorService().findHostBySerialNumber(remoteHostName);
        	if (h != null) {
        		remoteIp = h.getName()+" "+remoteIp;
        	}
        }
        try {
            le.setHost(IdpConfig.getConfig().getHostName());
        } catch (Exception e) {
            throw new IOException("Unable to get configuration"); //$NON-NLS-1$
        }
        le.info = info;
        le.setHost(serviceProvider);
        le.setClient(remoteIp);
        le.setProtocol(protocol);
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

