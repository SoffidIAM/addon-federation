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
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ssl.SslSocketConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.idp.radius.server.web.RadiusSslContextFactory;
import com.soffid.iam.addons.federation.idp.radius.server.web.RadiusUserServlet;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.ssl.SeyconKeyStore;

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
        String actualAddress = System.getProperty("soffid.idp.listen.address");

        RadiusSslContextFactory factory = new RadiusSslContextFactory(this.radiusServer.getCertificateCache());
        factory.setKeyStore(SeyconKeyStore.getKeyStoreFile().getPath());
        factory.setKeyStorePassword(SeyconKeyStore.getKeyStorePassword()
                .getPassword());
        factory.setKeyStoreType(SeyconKeyStore.getKeyStoreType());
        factory.setCertAlias("idp"); //$NON-NLS-1$
        factory.setNeedClientAuth(true);
        factory.setExcludeCipherSuites(new String[] {
        		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",        		
        });
//        factory.setIncludeCipherSuites(cipherSuites);
        SslSocketConnector connector = new SslSocketConnector(factory);

        connector.setPort(profile.getFreeRadiusPort().intValue());
        if (actualAddress != null)
        	connector.setHost(actualAddress);
        connector.setAcceptors(2);
        connector.setAcceptQueueSize(10);
        connector.setMaxIdleTime(60000);
        connector.setHandshakeTimeout(2000);
        connector.setLowResourcesMaxIdleTime(2000);
        connector.setSoLingerTime(10000);
        connector.setHostHeader(c.getHostName());
        connector.setRequestBufferSize( 64 * 1024);
        connector.setHeaderBufferSize( 64 * 1024);
        try {
        	String s = new RemoteServiceLocator().getServerService().getConfig("soffid.syncserver.bufferSize");
        	if (s != null) {
        		connector.setRequestBufferSize( Integer.parseInt(s));
        		connector.setHeaderBufferSize( Integer.parseInt(s));
        	}
        } catch (Throwable e) {}

        server.addConnector(connector);
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
		pool.setMaxQueued(15);
		server = new Server();
        server.setThreadPool(pool);
        server.setSendServerVersion(false);
	}

}
