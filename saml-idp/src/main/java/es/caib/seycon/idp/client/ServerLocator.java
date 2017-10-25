package es.caib.seycon.idp.client;

import java.io.IOException;
import java.net.URL;

import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.remote.URLManager;

public class ServerLocator {
    private static ServerLocator serverLocator;
    int roundRobin = 0;
    long lastLoookup = 0;
    private String[] serverHosts;
    
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

        serverHosts = Config.getConfig().getSeyconServerHostList();

        if (serverHosts == null || serverHosts.length == 0) {
            throw new es.caib.seycon.ng.exception.InternalErrorException("Missing seycon.server.list property at seycon.properties file"); //$NON-NLS-1$
        }
        lastLoookup = now;

    }

    public synchronized String getServer() throws InternalErrorException, IOException {
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
            }
        } while (roundRobin != first && first < serverHosts.length);
        lastLoookup = 0;
        throw new IOException("No server available"); //$NON-NLS-1$
    }
    
    public com.soffid.iam.remote.RemoteServiceLocator getRemoteServiceLocator() throws InternalErrorException, IOException {
    	return new com.soffid.iam.remote.RemoteServiceLocator(getServer());
    }
    
    public URL getServerUrl (String url) throws InternalErrorException, IOException {
    	URLManager um = new URLManager(getServer());
    	return um.getHttpURL(url);
    }
}
