package com.soffid.iam.federation.idp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.EventListener;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import net.shibboleth.utilities.jetty7.DelegateToApplicationSslContextFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.DispatcherType;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.SessionManager;
import org.eclipse.jetty.server.handler.ErrorHandler;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.server.ssl.SslSocketConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.slf4j.ILoggerFactory;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.ContextLoaderListener;
import org.xml.sax.SAXException;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.service.CertificateValidationService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.https.ApacheSslSocketFactory;
import es.caib.seycon.idp.session.SessionCallbackServlet;
import es.caib.seycon.idp.session.SessionListener;
import es.caib.seycon.idp.ui.ActivateUserAction;
import es.caib.seycon.idp.ui.ActivatedFormServlet;
import es.caib.seycon.idp.ui.AuthenticatedFilter;
import es.caib.seycon.idp.ui.CertificateAction;
import es.caib.seycon.idp.ui.CertificateForm;
import es.caib.seycon.idp.ui.DefaultServlet;
import es.caib.seycon.idp.ui.ErrorServlet;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.LogoutServlet;
import es.caib.seycon.idp.ui.PasswordChangeAction;
import es.caib.seycon.idp.ui.PasswordChangeForm;
import es.caib.seycon.idp.ui.PasswordChangeRequiredAction;
import es.caib.seycon.idp.ui.PasswordChangeRequiredForm;
import es.caib.seycon.idp.ui.PasswordChangedForm;
import es.caib.seycon.idp.ui.PasswordRecoveryAction;
import es.caib.seycon.idp.ui.PasswordRecoveryAction2;
import es.caib.seycon.idp.ui.PasswordRecoveryForm;
import es.caib.seycon.idp.ui.RegisterAction;
import es.caib.seycon.idp.ui.RegisterFormServlet;
import es.caib.seycon.idp.ui.RegisteredFormServlet;
import es.caib.seycon.idp.ui.SignatureAction;
import es.caib.seycon.idp.ui.SignatureForm;
import es.caib.seycon.idp.ui.UnauthenticatedFilter;
import es.caib.seycon.idp.ui.UserPasswordAction;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.idp.ui.oauth.OauthRequestAction;
import es.caib.seycon.idp.ui.oauth.OauthResponseAction;
import es.caib.seycon.idp.ui.openid.OpenIdRequestAction;
import es.caib.seycon.idp.ui.openid.OpenIdResponseAction;
import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ssl.SeyconKeyStore;

public class Main {

    private Server server;


    public void stop() throws Exception {
        for (Connector c: server.getConnectors())
        {
        	try {
        		c.stop();
        	} catch (Exception e) 
        	{
        		
        	}
        }
        server.stop();
    }

    public void start(String publicId, Dispatcher dispatcher) throws Exception{

        ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(Main.class.getClassLoader());
            
            System.out.println ("Staring IDP "+publicId); //$NON-NLS-1$
            
            IdpConfig c = IdpConfig.getConfig();
    
            c.setPublicId(publicId);
            c.setDispatcher(dispatcher);
            c.configure();
    
            configureLogger(c);
    
    
            ApacheSslSocketFactory.register();
    
            createConfigurationFiles(c);
    
            QueuedThreadPool pool = new QueuedThreadPool();
    
            server = new Server();
            server.setThreadPool(pool);
    
            String host = c.getHostName();
            Integer port = c.getStandardPort();
            Integer port2 = c.getClientCertPort();
    
            installSSLConnector(host, port);
            installClientCertConnector(host, port2);
    
            // Deploy war
            deployWar();
    
            // Start
            server.setSendServerVersion(false);
            server.start();
    
            if (server.isFailed() || server.getHandlers()[0].isFailed())
                System.out.println("Failed!!"); //$NON-NLS-1$
            else
                System.out.println("Started!!"); //$NON-NLS-1$
        } finally {
            if (oldClassLoader != null)
                Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
    
    }

    private void createConfigurationFiles(IdpConfig c)
            throws UnrecoverableKeyException, FileNotFoundException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, InternalErrorException, InvalidKeyException,
            IllegalStateException, NoSuchProviderException, SignatureException,
            SAXException, ParserConfigurationException, TransformerException {
        c.extractConfigFile("attribute-resolver.xml"); //$NON-NLS-1$
        c.extractConfigFile("handler.xml"); //$NON-NLS-1$
        c.generateFederationConfiguration();
    }

    private void configureLogger(IdpConfig c) throws FileNotFoundException,
            IOException, InternalErrorException {
        c.extractConfigFile("logging.xml"); //$NON-NLS-1$
        File logFile = new File(c.getConfDir(), "logging.xml"); //$NON-NLS-1$
        ILoggerFactory loggerContext = LoggerFactory.getILoggerFactory();
        /*
        loggerContext.reset();
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(loggerContext);
        try {
            configurator.doConfigure(new FileInputStream(logFile));
            System.out.println("Logging to " + c.getLogDir().getPath());
        } catch (JoranException e) {
            System.out.println("Unable to configure logger");
            e.printStackTrace();
        }
        loggerContext.start();
        */
        loggerContext.getLogger(Main.class.getName()).info("Starting server"); //$NON-NLS-1$
    }

    private void installSSLConnector(String host, Integer port)
            throws IOException, FileNotFoundException {
        installConnector(host, port, false);
    }

    private void installConnector(String host, Integer port,
            boolean wantClientAuth) throws IOException, FileNotFoundException {
        System.out.println("Listening on socket " + host + ":" + port + "..."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        Log.getLog().info("Listening on socket " + host + ":" + port + "..."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

        DelegateToApplicationSslContextFactory factory = new DelegateToApplicationSslContextFactory();
        factory.setKeyStore(SeyconKeyStore.getKeyStoreFile().getPath());
        factory.setKeyStorePassword(SeyconKeyStore.getKeyStorePassword()
                .getPassword());
        factory.setKeyStoreType(SeyconKeyStore.getKeyStoreType());
        factory.setCertAlias("idp"); //$NON-NLS-1$
        factory.setWantClientAuth(wantClientAuth);
        SslSocketConnector connector = new SslSocketConnector(factory);

        connector.setPort(port == null ? 443 : port.intValue());
        // connector.setHost(host);
        connector.setAcceptors(2);
        connector.setAcceptQueueSize(10);
        connector.setMaxIdleTime(60000);

        connector.setHostHeader(host);

        server.addConnector(connector);
    }

    private void installClientCertConnector(String host, Integer port)
            throws IOException, FileNotFoundException {
        installConnector(host, port, true);
    }

    private void deployWar() throws FileNotFoundException, IOException,
            UnrecoverableKeyException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException,
            InternalErrorException, InvalidKeyException, IllegalStateException,
            NoSuchProviderException, SignatureException {

        ServletContextHandler ctx = new ServletContextHandler(
                ServletContextHandler.SESSIONS);
        ctx.setContextPath("/"); //$NON-NLS-1$
        ctx.setClassLoader(Main.class.getClassLoader());
        server.setHandler(ctx);
        ctx.setDisplayName("Soffid SAML Identity Provider"); //$NON-NLS-1$
        ctx.setInitParameter(SessionManager.__SessionCookieProperty, "SoffidIDPSessionId"); //$NON-NLS-1$
        IdpConfig c = IdpConfig.getConfig();

        File f1 = c.extractConfigFile("internal.xml"); //$NON-NLS-1$
        File f2 = c.extractConfigFile("service.xml"); //$NON-NLS-1$
        String conf = f1.toURI().toString() + "; " + f2.toURI().toString() //$NON-NLS-1$
                + ";"; //$NON-NLS-1$
        System.out.println("Confg = " + conf); //$NON-NLS-1$
        ctx.setInitParameter("contextConfigLocation", conf); //$NON-NLS-1$

        EventListener el = new ContextLoaderListener();
        ctx.addEventListener(el);
        // Filters

        FilterHolder f = new FilterHolder(
                edu.internet2.middleware.shibboleth.common.log.SLF4JMDCCleanupFilter.class);
        f.setName("JCleanupFilter"); //$NON-NLS-1$
        ctx.addFilter(f, "/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        f = new FilterHolder(
                edu.internet2.middleware.shibboleth.idp.session.IdPSessionFilter.class);
        f.setName("IdPSessionFilter"); //$NON-NLS-1$
        ctx.addFilter(f, "/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        f = new FilterHolder(
                edu.internet2.middleware.shibboleth.idp.util.NoCacheFilter.class);
        f.setName("IdPNoCacheFilter"); //$NON-NLS-1$
        ctx.addFilter(f, "/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        f = new FilterHolder(AuthenticatedFilter.class);
        f.setName("AutenticatedFilter"); //$NON-NLS-1$
        ctx.addFilter(f, "/protected/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        f = new FilterHolder(UnauthenticatedFilter.class);
        f.setName("UnautenticatedFilter"); //$NON-NLS-1$
        ctx.addFilter(f, "/profile/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        f = new FilterHolder(LanguageFilter.class);
        f.setName("LanguageFilter"); //$NON-NLS-1$
        ctx.addFilter(f, "/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        // Servlets
        ServletHolder servlet = new ServletHolder(
                edu.internet2.middleware.shibboleth.common.profile.ProfileRequestDispatcherServlet.class);
        servlet.setInitOrder(1);
        servlet.setName("ProfileRequestDispatcher"); //$NON-NLS-1$
        ctx.addServlet(servlet, "/profile/*"); //$NON-NLS-1$

        servlet = new ServletHolder(
                edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine.class);
        servlet.setInitOrder(2);
        servlet.setName("AuthenticationEngine"); //$NON-NLS-1$
        ctx.addServlet(servlet, "/AuthnEngine"); //$NON-NLS-1$

        servlet = new ServletHolder(
                edu.internet2.middleware.shibboleth.idp.StatusServlet.class);
        servlet.setInitOrder(2);
        servlet.setName("Status"); //$NON-NLS-1$
        servlet.setInitParameter("AllowedIPs", //$NON-NLS-1$
                "127.0.0.1/32 ::1/128"); //$NON-NLS-1$
        ctx.addServlet(servlet, "/status"); //$NON-NLS-1$

        ctx.addServlet(LoginServlet.class, LoginServlet.URI);
        ctx.addServlet(UserPasswordFormServlet.class,
                UserPasswordFormServlet.URI);
        ctx.addServlet(UserPasswordAction.class, UserPasswordAction.URI);
        ctx.addServlet(PasswordChangeRequiredForm.class,
                PasswordChangeRequiredForm.URI);
        ctx.addServlet(PasswordChangeRequiredAction.class,
                PasswordChangeRequiredAction.URI);
        ctx.addServlet(CertificateForm.class, CertificateForm.URI);
        ctx.addServlet(CertificateAction.class, CertificateAction.URI);
        ctx.addServlet(SignatureForm.class, SignatureForm.URI);
        ctx.addServlet(SignatureAction.class, SignatureAction.URI);
        ctx.addServlet(PasswordChangeForm.class, PasswordChangeForm.URI);
        ctx.addServlet(PasswordChangeAction.class, PasswordChangeAction.URI);
        ctx.addServlet(PasswordChangedForm.class, PasswordChangedForm.URI);
        ctx.addServlet(LogoutServlet.class, LogoutServlet.URI);
        ctx.addServlet(RegisterFormServlet.class, RegisterFormServlet.URI);
        ctx.addServlet(RegisterAction.class, RegisterAction.URI);
        ctx.addServlet(RegisteredFormServlet.class, RegisteredFormServlet.URI);
        ctx.addServlet(ActivateUserAction.class, ActivateUserAction.URI);
        ctx.addServlet(ActivatedFormServlet.class, ActivatedFormServlet.URI);
        ctx.addServlet(PasswordRecoveryAction.class, PasswordRecoveryAction.URI);
        ctx.addServlet(PasswordRecoveryForm.class, PasswordRecoveryForm.URI);
        ctx.addServlet(PasswordRecoveryAction2.class, PasswordRecoveryAction2.URI);
        ctx.addServlet(SessionCallbackServlet.class, SessionCallbackServlet.URI);
        ctx.addServlet(OpenIdRequestAction.class, OpenIdRequestAction.URI);
        ctx.addServlet(OpenIdResponseAction.class, OpenIdResponseAction.URI);
        ctx.addServlet(OauthRequestAction.class, OauthRequestAction.URI);
        ctx.addServlet(OauthResponseAction.class, OauthResponseAction.URI);

        servlet = new ServletHolder(ErrorServlet.class);
        servlet.setName("error"); //$NON-NLS-1$
        ctx.addServlet(servlet, ErrorServlet.URI); //$NON-NLS-1$

        servlet = new ServletHolder(DefaultServlet.class);
        servlet.setName("default"); //$NON-NLS-1$
        ctx.addServlet(servlet, "/*"); //$NON-NLS-1$

        ctx.setErrorHandler(new ErrorHandler());

        /**
         * <!-- Send request to the EntityID to the SAML metadata handler. -->
         * <servlet> <servlet-name>shibboleth_jsp</servlet-name>
         * <jsp-file>/shibboleth.jsp</jsp-file> </servlet>
         * 
         * <servlet-mapping> <servlet-name>shibboleth_jsp</servlet-name>
         * <url-pattern>/shibboleth</url-pattern> </servlet-mapping>
         * 
         * <error-page> <error-code>500</error-code>
         * <location>/error.jsp</location> </error-page>
         * 
         * <error-page> <error-code>404</error-code>
         * <location>/error-404.jsp</location> </error-page>
         */

        ctx.setSessionHandler(new SessionHandler());
        ctx.getSessionHandler().getSessionManager().setMaxInactiveInterval(1200); // 20 minutes timeout
        ctx.getSessionHandler().getSessionManager().addEventListener(new SessionListener());
        
    }

    private void updateTrustedCerts() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, InternalErrorException
    {
    	char password [] = "changeit".toCharArray();
    	Config config = Config.getConfig();
        File ksFile = new File(config.getHomeDir(), "cacerts");

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream (ksFile), password);
        RemoteServiceLocator rsl = new RemoteServiceLocator();
        CertificateValidationService vds = rsl.getCertificateValidationService();
        for (X509Certificate cert: vds.getRootCertificateList())
        {
        	String name = cert.getSubjectX500Principal().getName();
        	ks.setCertificateEntry(name, cert);
        }
        ks.store(new FileOutputStream(ksFile), password);
    }
}
