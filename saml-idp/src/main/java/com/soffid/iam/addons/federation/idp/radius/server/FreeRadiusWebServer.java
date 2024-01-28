package com.soffid.iam.addons.federation.idp.radius.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.idp.radius.server.web.RadiusSslContextFactory;
import com.soffid.iam.addons.federation.idp.radius.server.web.RadiusUserServlet;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.ssl.SeyconKeyStore;
import com.soffid.iam.sync.jetty.ProxyConnectionFactory;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class FreeRadiusWebServer {
	org.apache.commons.logging.Log log = LogFactory.getLog(getClass());
	
	private SAMLProfile profile;
	private Server server;
	private ServletContextHandler ctx;

	private RadiusServer radiusServer;

	public FreeRadiusWebServer(SAMLProfile radius, RadiusServer rs) {
		this.profile = radius;
		this.radiusServer = rs;
	}

	public void start() throws Exception {
        
        createServer();

        createConnector();
        
        createContext();
        
        server.start();
	}

	private void createConnector() throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		IdpConfig c = IdpConfig.getConfig();
		
        log.info("Listening on socket " + profile.getFreeRadiusPort() + "..."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

    	HttpConfiguration httpConfig = new HttpConfiguration();
    	httpConfig.setSendServerVersion(false);
    	
    	SecureRequestCustomizer src = new SecureRequestCustomizer(false);
    	httpConfig.addCustomizer(src);
    	
    	HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfig);

    	RadiusSslContextFactory factory = new RadiusSslContextFactory(radiusServer.getCertificateCache());
        factory.setKeyStorePath(SeyconKeyStore.getKeyStoreFile().getPath());
        factory.setKeyStorePassword(SeyconKeyStore.getKeyStorePassword()
                .getPassword());
        factory.setKeyStoreType(SeyconKeyStore.getKeyStoreType());
        factory.setCertAlias("idp"); //$NON-NLS-1$
        factory.setNeedClientAuth(true);
        factory.setExcludeCipherSuites(new String[] {
        		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",        		
        });
        
    	SslConnectionFactory tls = new SslConnectionFactory(factory, http11.getProtocol());
    	ServerConnector connector;
    	if (enableProxyProtocol()) {
    		String trustedProxy = System.getenv("PROXY_PROTOCOL_ENABLED");
    		if ("true".equalsIgnoreCase(trustedProxy)) {
	    		log.warn("Accepting proxy requests from ANY server. It is a potential security vulnerability");
	    		ProxyConnectionFactory proxy = new ProxyConnectionFactory(tls.getProtocol());
	    		connector = new ServerConnector(server, proxy, tls, http11);
    		} else {
    			log.info("Accepting proxy requests from "+trustedProxy);
	    		ProxyConnectionFactory proxy = new ProxyConnectionFactory(tls.getProtocol(), trustedProxy);
	    		connector = new ServerConnector(server, proxy, tls, http11);
    		}
    	} else {
    		connector = new ServerConnector(server, tls, http11);
    	}

    	//        factory.setIncludeCipherSuites(cipherSuites);

        connector.setPort(profile.getFreeRadiusPort().intValue());
        connector.setAcceptQueueSize(10);

        server.addConnector(connector);
	}

	private boolean enableProxyProtocol() {
		return null != System.getenv("PROXY_PROTOCOL_ENABLED");
	}

	private void createContext() throws FileNotFoundException, IOException, UnrecoverableKeyException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, InternalErrorException,
			InvalidKeyException, NoSuchProviderException, SignatureException {
		ctx = new ServletContextHandler(
                ServletContextHandler.SESSIONS);
        
        ctx.setContextPath("/soffidradius"); //$NON-NLS-1$
        ctx.setClassLoader(getClass().getClassLoader());
        server.setHandler(ctx);
        ctx.setDisplayName("Soffid Free radius adapter"); //$NON-NLS-1$
        IdpConfig c = IdpConfig.getConfig();

        ctx.addServlet(RadiusUserServlet.class, "/user/*");
        ctx.setAttribute("radiusServer", radiusServer);
	}

	private void createServer() {
		QueuedThreadPool pool = new QueuedThreadPool();
		pool.setMaxThreads(10);
		pool.setLowThreadsThreshold(2);
		server = new Server(pool);
	}

}
