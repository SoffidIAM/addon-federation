package es.caib.seycon.idp.client;

import java.io.IOException;
import java.net.URL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.remote.URLManager;

public class ServerLocator {
    private static ServerLocator serverLocator;
    int roundRobin = 0;
    long lastLoookup = 0;
    private String[] serverHosts;
    
    Log log = LogFactory.getLog(getClass());
    private ServerLocator () {
        
    }

    public static ServerLocator getInstance() {
        if (serverLocator == null)
            serverLocator = new ServerLocator ();
        return serverLocator;
    }
    
    
    private void updateServerList() throws IOException, IOException, es.caib.seycon.ng.exception.InternalErrorException {
        long now = System.currentTimeMillis();
        if (now < lastLoookup + 300000) // Cache 5 minutos
            return;

//        log.info ("Updating server list");
        String list = Config.getConfig().getRawSeyconServerList();
        if (list != null) {
        	String[] split = list.split("[, ]+"); //$NON-NLS-1$
        	serverHosts = new String[split.length];
        	for (int i = 0; i < split.length; i++) {
        		serverHosts[i] = split[i];
        	}
        }


        if (serverHosts == null || serverHosts.length == 0) {
            throw new es.caib.seycon.ng.exception.InternalErrorException("Missing seycon.server.list property at seycon.properties file"); //$NON-NLS-1$
        }
        lastLoookup = now;
    }

    public synchronized String getServer() throws InternalErrorException, IOException {
    	IOException lastException = null;
        updateServerList();
        
        if (roundRobin >= serverHosts.length)
            roundRobin = 0;
        int first = roundRobin;
        do {
            String server = serverHosts[roundRobin];
            roundRobin++;
            if (roundRobin >= serverHosts.length)
                roundRobin = 0;
            try {
            	RemoteServiceLocator rsl = new RemoteServiceLocator(server);
            	rsl.getServerService();
            	return server;
            } catch (IOException e) {
            	lastException = e;
            	log.info("Received error ",e);
            }
        } while (roundRobin != first && first < serverHosts.length);
        lastLoookup = 0;
        if (lastException == null)
            throw new IOException("No server available"); //$NON-NLS-1$
        else
        	throw new IOException("No server available", lastException); //$NON-NLS-1$
    }
    
    public com.soffid.iam.remote.RemoteServiceLocator getRemoteServiceLocator() throws InternalErrorException, IOException {
    	return new com.soffid.iam.remote.RemoteServiceLocator(getServer());
    }
    
    public URL getServerUrl (String url) throws InternalErrorException, IOException {
    	URLManager um = new URLManager(getServer());
    	return um.getHttpURL(url);
    }
}
