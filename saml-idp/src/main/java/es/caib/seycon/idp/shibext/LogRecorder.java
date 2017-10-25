package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import javax.servlet.http.HttpSession;

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

    LinkedList<LogEntry> logs = new LinkedList<LogEntry>();
    Map<String,LogEntry> activeLogs = new HashMap<String, LogEntry>();

    public static LogRecorder getInstance() {
        if (instance == null)
            instance = new LogRecorder();
        return instance;
    }

    public synchronized void addSuccessLogEntry(String user, String authMethod, String serviceProvider,
            String remoteIp, HttpSession session) throws IOException {
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
        
        le.info = String.format("ServiceProvider: %s Method: %s", serviceProvider, authMethod); //$NON-NLS-1$
        le.setHost(config.getHostName());
        le.setClient(remoteIp);
        le.setProtocol("SAML"); //$NON-NLS-1$
        le.setDate(new Date());
        le.SessionId = le.getHost() + "-" + System.currentTimeMillis(); //$NON-NLS-1$
        le.type = LogEntry.LOGON;
        le.setUser(user);
        logs.addLast(le);
        
        LogEntry le2 = new LogEntry();
        le2.info = String.format("ServiceProvider: %s Method: %s", serviceProvider, authMethod); //$NON-NLS-1$
        le2.setHost(config.getHostName());
        le2.setClient(remoteIp);
        le2.setProtocol("SAML"); //$NON-NLS-1$
        le2.setDate(new Date());
        le2.SessionId = le.getHost() + "-" + System.currentTimeMillis(); //$NON-NLS-1$
        le2.type = LogEntry.LOGOFF;
        le2.setUser(user);
        activeLogs.put (session.getId(), le2);
    }

    public synchronized void keepAliveLogSession(HttpSession session) throws IOException {
    	if (session != null)
    	{
    		LogEntry le = activeLogs.get(session.getId());
    		if (le != null)
    			le.setDate(new Date());
    	}
    }

    public synchronized void closeSession (HttpSession session) 
    {
    	if (session != null)
    	{
    		LogEntry le = activeLogs.get(session.getId());
    		if (le != null)
    		{
    			logs.add(le);
    			activeLogs.remove(session.getId());
    		}
    	}
    }

    public synchronized void addLogoffEntry(String user, String authMethod,
            String remoteIp) throws IOException {
        LogEntry le = new LogEntry();
        le.setClient(remoteIp);
        try {
            le.setHost(IdpConfig.getConfig().getHostName());
        } catch (Exception e) {
            throw new IOException("Unable to get configuration"); //$NON-NLS-1$
        }
        le.info = ""; //$NON-NLS-1$
        le.setHost(config.getHostName());
        le.setClient(remoteIp);
        le.setProtocol("HTTP"); //$NON-NLS-1$
        le.setDate(new Date());
        le.SessionId = le.getHost() + "-" + System.currentTimeMillis(); //$NON-NLS-1$
        le.type = LogEntry.LOGOFF;
        le.setUser(user);
        logs.addLast(le);
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
        logs.addLast(le);
    }

    public synchronized Collection<es.caib.seycon.ng.sync.intf.LogEntry> getLogs(Date d) {
        boolean repeat;
        if (d != null) {
            do {
                repeat = false;
                if (!logs.isEmpty()) {
                    LogEntry le = logs.getFirst();
                    int counter = 0;
                	while (le.getType() == LogEntry.LOGOFF)
                	{
                		counter ++;
                		if (counter >= logs.size())
                			return logs;
                		le = logs.get(counter);
                	}
                    if (le.getDate().before(d) || le.getDate().equals(d)) {
                   		while (counter >= 0)
                   		{
                            logs.removeFirst();
                            counter --;
                  		}
                        repeat = true;
                   	}
                }
            } while (repeat);
        }
        return logs;
    }
}

