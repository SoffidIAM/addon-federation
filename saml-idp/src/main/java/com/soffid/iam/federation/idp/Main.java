package com.soffid.iam.federation.idp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.URIParameter;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.EnumSet;
import java.util.EventListener;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletContext;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.eclipse.jetty.http.security.Constraint;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.SpnegoLoginService;
import org.eclipse.jetty.security.authentication.SpnegoAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.DispatcherType;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.SessionManager;
import org.eclipse.jetty.server.bio.SocketConnector;
import org.eclipse.jetty.server.session.HashSessionManager;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.server.ssl.SslSocketConnector;
import org.eclipse.jetty.servlet.ErrorPageErrorHandler;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.component.LifeCycle;
import org.eclipse.jetty.util.component.LifeCycle.Listener;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.slf4j.ILoggerFactory;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.ContextLoaderListener;
import org.xml.sax.SAXException;

import com.soffid.iad.addons.federation.idp.tacacs.TacacsServer;
import com.soffid.iad.addons.federation.idp.tacacs.TacacsServerListener;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.KerberosKeytab;
import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;
import com.soffid.iam.addons.federation.idp.radius.server.FreeRadiusWebServer;
import com.soffid.iam.addons.federation.idp.radius.server.RadiusServer;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.ssl.SeyconKeyStore;
import com.soffid.iam.sync.engine.kerberos.ChainConfiguration;
import com.soffid.iam.utils.Security;

import es.caib.seycon.idp.cas.LoginEndpoint;
import es.caib.seycon.idp.cas.ServiceValidateEndpoint;
import es.caib.seycon.idp.cas.ValidateEndpoint;
import es.caib.seycon.idp.cert.DelegateToApplicationSslContextFactory;
import es.caib.seycon.idp.config.CustomSpnegoLoginService;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.https.ApacheSslSocketFactory;
import es.caib.seycon.idp.openid.server.AuthorizationEndpoint;
import es.caib.seycon.idp.openid.server.ConfigurationEndpoint;
import es.caib.seycon.idp.openid.server.ImpersonationEndpoint;
import es.caib.seycon.idp.openid.server.JWKEndpoint;
import es.caib.seycon.idp.openid.server.LogoutEndpoint;
import es.caib.seycon.idp.openid.server.RegisterEndpoint;
import es.caib.seycon.idp.openid.server.RevokeEndpoint;
import es.caib.seycon.idp.openid.server.SessionCookieEndpoint;
import es.caib.seycon.idp.openid.server.TokenEndpoint;
import es.caib.seycon.idp.openid.server.TokenIntrospectionEndpoint;
import es.caib.seycon.idp.openid.server.UserInfoEndpoint;
import es.caib.seycon.idp.session.SessionCallbackServlet;
import es.caib.seycon.idp.session.SessionListener;
import es.caib.seycon.idp.ui.ActivateUserAction;
import es.caib.seycon.idp.ui.ActivatedFormServlet;
import es.caib.seycon.idp.ui.AuthenticatedFilter;
import es.caib.seycon.idp.ui.CancelAction;
import es.caib.seycon.idp.ui.CertificateAction;
import es.caib.seycon.idp.ui.ChangeUserAction;
import es.caib.seycon.idp.ui.ConsentAction;
import es.caib.seycon.idp.ui.ConsentFormServlet;
import es.caib.seycon.idp.ui.DefaultServlet;
import es.caib.seycon.idp.ui.ErrorServlet;
import es.caib.seycon.idp.ui.IframeSession;
import es.caib.seycon.idp.ui.KeepAliveServlet;
import es.caib.seycon.idp.ui.LogFilter;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.LogoutServlet;
import es.caib.seycon.idp.ui.MetadataServlet;
import es.caib.seycon.idp.ui.NtlmAction;
import es.caib.seycon.idp.ui.OTPAction;
import es.caib.seycon.idp.ui.P3PFilter;
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
import es.caib.seycon.idp.ui.RootServlet;
import es.caib.seycon.idp.ui.TenantFilter;
import es.caib.seycon.idp.ui.UnauthenticatedFilter;
import es.caib.seycon.idp.ui.UserAction;
import es.caib.seycon.idp.ui.UserInfoForm;
import es.caib.seycon.idp.ui.UserPasswordAction;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.idp.ui.broker.QueryUserIdPServlet;
import es.caib.seycon.idp.ui.broker.SAMLSSOPostServlet;
import es.caib.seycon.idp.ui.broker.SAMLSSORequest;
import es.caib.seycon.idp.ui.cred.ProtectedUserCredentialRegisterServlet;
import es.caib.seycon.idp.ui.cred.ProtectedValidateRegisteredCredential;
import es.caib.seycon.idp.ui.cred.RegisterCredential;
import es.caib.seycon.idp.ui.cred.UserCredentialRegisterServlet;
import es.caib.seycon.idp.ui.cred.UserPushCredentialRegisterServlet;
import es.caib.seycon.idp.ui.cred.UserPushCredentialServlet;
import es.caib.seycon.idp.ui.cred.ValidateCredential;
import es.caib.seycon.idp.ui.cred.ValidateRegisteredCredential;
import es.caib.seycon.idp.ui.cred.ValidateUserPushCredentialServlet;
import es.caib.seycon.idp.ui.oauth.OauthRequestAction;
import es.caib.seycon.idp.ui.oauth.OauthResponseAction;
import es.caib.seycon.idp.ui.rememberPassword.PasswordRememberAction;
import es.caib.seycon.idp.ui.rememberPassword.PasswordRememberForm;
import es.caib.seycon.idp.ui.rememberPassword.PasswordResetAction;
import es.caib.seycon.idp.ui.rememberPassword.PasswordResetForm;
import es.caib.seycon.ng.exception.InternalErrorException;

public class Main {

    private Server server;
	private Throwable lastException = null;
	private Listener listener = new Listener() {
		public void lifeCycleStarting(LifeCycle event) {
		}

		public void lifeCycleStarted(LifeCycle event) {
		}

		public void lifeCycleFailure(LifeCycle event, Throwable cause) {
			lastException = cause;
		}

		public void lifeCycleStopping(LifeCycle event) {
		}

		public void lifeCycleStopped(LifeCycle event) {
		}
		
	};

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

    public void start(String publicId, com.soffid.iam.api.System dispatcher) throws Exception
    {
    	ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(Main.class.getClassLoader());
            
            System.out.println ("Starting IDP "+publicId); //$NON-NLS-1$
            
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
//            server.setSessionIdManager(new PersistentSessionIdManager());
            String host = c.getHostName();
            Integer port = c.getStandardPort();
            
            boolean plainSocket = c.getFederationMember().getDisableSSL() != null &&
            		c.getFederationMember().getDisableSSL().booleanValue();
            if ("false".equals(System.getProperty("soffid.idp.listen.ssl")))
                installPlainConnector(host, port);
            else
            	installClientCertConnector(host, port);
    
            // Deploy war
            ServletContextHandler ctx = deployWar(plainSocket);
    
            // Start
            server.setSendServerVersion(false);
            server.addLifeCycleListener(listener );
            lastException = null;
            server.start();
    
            if (server.isFailed() || server.getHandlers()[0].isFailed())
            {
            	if (lastException != null)
            		throw new InternalErrorException("Error starting IdP service", lastException);
            	else
            		throw new InternalErrorException("Unknown error starting IdP service");
            	
            }
            
            SAMLProfile radius = useRadiusProfile();
            if (radius != null && Boolean.TRUE.equals(radius.getEnabled())) {
            	createRadiusServer (radius, ctx.getServletContext() );
            }
            SAMLProfile tacacs = useTacacsProfile();
            if (tacacs != null && Boolean.TRUE.equals(tacacs.getEnabled())) {
            	createTacacsServer (tacacs, ctx.getServletContext() );
            }
        } finally {
            if (oldClassLoader != null)
                Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
    
    }

    private void createRadiusServer(SAMLProfile radius, ServletContext ctx ) throws Exception {
    	RadiusServer rs = new RadiusServer();
    	if (radius.getAcctPort() != null)
    		rs.setAcctPort(radius.getAcctPort());
    	if (radius.getAuthPort() != null)
    		rs.setAuthPort(radius.getAuthPort());
    	if (radius.getSecurePort() != null)
    		rs.setSecurePort(radius.getSecurePort());
    	rs.setServletContext(ctx);
    	rs.start(true, true);
    	
    	if (radius.getFreeRadiusPort() != null) {
    		FreeRadiusWebServer s = new FreeRadiusWebServer(radius, rs);
    		s.start();
    	}
	}

    private void createTacacsServer(SAMLProfile radius, ServletContext ctx ) {
    	TacacsServerListener rs = new TacacsServerListener();
    	if (radius.getAuthPort() != null)
    		rs.setAuthPort(radius.getAuthPort());
    	rs.setServletContext(ctx);
    	rs.setSsl(Boolean.TRUE.equals(radius.getSsl()));
    	rs.start();
	}

	private void createConfigurationFiles(IdpConfig c)
            throws UnrecoverableKeyException, FileNotFoundException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, InternalErrorException, InvalidKeyException,
            IllegalStateException, NoSuchProviderException, SignatureException,
            SAXException, ParserConfigurationException, TransformerException {
//        c.extractConfigFile("attribute-resolver.xml"); //$NON-NLS-1$
//        c.extractConfigFile("handler.xml"); //$NON-NLS-1$
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

    private void installConnector(String host, Integer port,
            boolean wantClientAuth) throws IOException, FileNotFoundException {
        System.out.println("Listening on socket " + host + ":" + port + "..."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        Log.getLog().info("Listening on socket " + host + ":" + port + "..."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

        Long actualPort = Long.getLong("soffid.idp.listen.port");
        String actualAddress = System.getProperty("soffid.idp.listen.address");

        DelegateToApplicationSslContextFactory factory = new DelegateToApplicationSslContextFactory();
        factory.setKeyStore(SeyconKeyStore.getKeyStoreFile().getPath());
        factory.setKeyStorePassword(SeyconKeyStore.getKeyStorePassword()
                .getPassword());
        factory.setKeyStoreType(SeyconKeyStore.getKeyStoreType());
        factory.setCertAlias("idp"); //$NON-NLS-1$
        factory.setWantClientAuth(wantClientAuth && actualPort == null);
        factory.setExcludeCipherSuites(new String[] {
        		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",        		
        });
//        factory.setIncludeCipherSuites(cipherSuites);
        SslSocketConnector connector = new SslSocketConnector(factory);

        connector.setPort(actualPort != null ? actualPort.intValue():  port == null ? 443 : port.intValue());
        if (actualAddress != null)
        	connector.setHost(actualAddress);
        connector.setAcceptors(2);
        connector.setAcceptQueueSize(10);
        connector.setMaxIdleTime(60000);
        connector.setHandshakeTimeout(2000);
        connector.setLowResourcesMaxIdleTime(2000);
        connector.setSoLingerTime(10000);
        connector.setHostHeader(host);

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

    private void installPlainConnector(String host, Integer port) throws IOException, FileNotFoundException {
        System.out.println("Listening on socket " + host + ":" + port + "..."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        Log.getLog().info("Listening on socket " + host + ":" + port + "..."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

        Long actualPort = Long.getLong("soffid.idp.listen.port");
        String actualAddress = System.getProperty("soffid.idp.listen.address");

        SocketConnector connector = new SocketConnector();

        connector.setRequestBufferSize( 64 * 1024);
        connector.setHeaderBufferSize( 64 * 1024);
        try {
        	String s = new RemoteServiceLocator().getServerService().getConfig("soffid.syncserver.bufferSize");
        	if (s != null) {
        		connector.setRequestBufferSize( Integer.parseInt(s));
        		connector.setHeaderBufferSize( Integer.parseInt(s));
        	}
        } catch (Throwable e) {}
        
        connector.setPort(actualPort != null ? actualPort.intValue():  port == null ? 443 : port.intValue());
        if (actualAddress != null)
        	connector.setHost(actualAddress);
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

    protected ServletContextHandler deployWar(boolean plainSocket) throws FileNotFoundException, IOException,
            UnrecoverableKeyException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException,
            InternalErrorException, InvalidKeyException, IllegalStateException,
            NoSuchProviderException, SignatureException, LoginException, InstantiationException, IllegalAccessException, ClassNotFoundException {
    	
        ServletContextHandler ctx = new ServletContextHandler(
                ServletContextHandler.SESSIONS);
        
        ctx.addLifeCycleListener(listener );

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
        ctx.setInitParameter("contextConfigLocation", conf); //$NON-NLS-1$

        EventListener el = new SoffidContextLoaderListener();
        ctx.addEventListener(el);
        
        // Filters
        FilterHolder log = new FilterHolder(LogFilter.class);
        log.setName("logFilter");
        ctx.addFilter(log, "/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        FilterHolder f = new FilterHolder(P3PFilter.class);
        f.setName("P3PFilter"); //$NON-NLS-1$
//        ctx.addFilter(f, "/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        f = new FilterHolder(TenantFilter.class);
        f.setName("TenantFilter");
        f.setInitParameter("tenant", Security.getCurrentTenantName());
        f.setInitParameter("port", c.getFederationMember().getStandardPort());
        f.setInitParameter("host", c.getFederationMember().getHostName());
        ctx.addFilter(f, "/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$
        
        f = new FilterHolder(
                edu.internet2.middleware.shibboleth.common.log.SLF4JMDCCleanupFilter.class);
        f.setName("JCleanupFilter"); //$NON-NLS-1$
        ctx.addFilter(f, "/*", EnumSet.of(DispatcherType.REQUEST)); //$NON-NLS-1$

        f = new FilterHolder(SoffidIdPSessionFilter.class);
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

        ServletHolder servlet;
        if (useSamldProfile())
        {
	        configureSamlProfile(ctx);
        }
        SAMLProfile openIdProfile = useOpenidProfile();
        if (openIdProfile != null)
        {
        	configureOpenidProfile(ctx, openIdProfile);
        }
        final SAMLProfile casProfile = useCasProfile();
		if (casProfile != null) {
        	configureCasProfile(ctx, casProfile);
        }
        ctx.addServlet(LoginServlet.class, LoginServlet.URI);
        ctx.addServlet(UserInfoForm.class, UserInfoForm.URI);
        ctx.addServlet(ConsentAction.class, ConsentAction.URI);
        ctx.addServlet(ConsentFormServlet.class, ConsentFormServlet.URI);
        
        // Credentials
        ctx.addServlet(RegisterCredential.class, RegisterCredential.URI);
        ctx.addServlet(ValidateCredential.class, ValidateCredential.URI);
        ctx.addServlet(UserCredentialRegisterServlet.class, UserCredentialRegisterServlet.URI);
        ctx.addServlet(ValidateRegisteredCredential.class, ValidateRegisteredCredential.URI);
        ctx.addServlet(ProtectedUserCredentialRegisterServlet.class, ProtectedUserCredentialRegisterServlet.URI);
        ctx.addServlet(ProtectedValidateRegisteredCredential.class, ProtectedValidateRegisteredCredential.URI);
        
        // Push tokens
        
        ctx.addServlet(UserPushCredentialRegisterServlet.class, UserPushCredentialRegisterServlet.URI);
        ctx.addServlet(UserPushCredentialServlet.class, UserPushCredentialServlet.URI);
        ctx.addServlet(ValidateUserPushCredentialServlet.class, ValidateUserPushCredentialServlet.URI);
        
        
        // Standard UI actions
        ctx.addServlet(CancelAction.class, CancelAction.URI);
        ctx.addServlet(UserPasswordFormServlet.class,
                UserPasswordFormServlet.URI);
        ctx.addServlet(UserPasswordAction.class, UserPasswordAction.URI);
        ctx.addServlet(UserAction.class, UserAction.URI);
        ctx.addServlet(ChangeUserAction.class, ChangeUserAction.URI);
        ctx.addServlet(OTPAction.class, OTPAction.URI);
        ctx.addServlet(PasswordChangeRequiredForm.class,
                PasswordChangeRequiredForm.URI);
        ctx.addServlet(PasswordChangeRequiredAction.class,
                PasswordChangeRequiredAction.URI);
        ctx.addServlet(CertificateAction.class, CertificateAction.URI);
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
        ctx.addServlet(OauthRequestAction.class, OauthRequestAction.URI);
        ctx.addServlet(OauthResponseAction.class, OauthResponseAction.URI);
        
        ctx.addServlet(QueryUserIdPServlet.class, QueryUserIdPServlet.URI);
        ctx.addServlet(SAMLSSOPostServlet.class, SAMLSSOPostServlet.URI);
        ctx.addServlet(SAMLSSORequest.class, SAMLSSORequest.URI);
        
        try {
            ctx.addServlet(PasswordRememberAction.class, PasswordRememberAction.URI);
            ctx.addServlet(PasswordRememberForm.class, PasswordRememberForm.URI);
            ctx.addServlet(PasswordResetAction.class, PasswordResetAction.URI);
            ctx.addServlet(PasswordResetForm.class, PasswordResetForm.URI);
        } catch (NoClassDefFoundError e) {
        }

        servlet = new ServletHolder(ErrorServlet.class);
        servlet.setName("error"); //$NON-NLS-1$
        ctx.addServlet(servlet, ErrorServlet.URI); //$NON-NLS-1$

        servlet = new ServletHolder(DefaultServlet.class);
        servlet.setName("default"); //$NON-NLS-1$
        ctx.addServlet(servlet, "/*"); //$NON-NLS-1$

        ErrorPageErrorHandler errorHandler = new ErrorPageErrorHandler();
        ctx.setErrorHandler(errorHandler);
        
        errorHandler.addErrorPage(400, ErrorServlet.URI);
        errorHandler.addErrorPage(401, UserPasswordFormServlet.URI);
        errorHandler.addErrorPage(Throwable.class, ErrorServlet.URI);
        for (int i = 402; i <= 416; i++)
        	errorHandler.addErrorPage(i, ErrorServlet.URI);
        for (int i = 500; i <= 505; i++)
        	errorHandler.addErrorPage(i, ErrorServlet.URI);
        
        if (needsKerberos(c))
        	configureSpnego(ctx, c);
        	
        ctx.setSessionHandler(new SessionHandler());
        int timeout = c.getFederationMember().getSessionTimeout() == null ? 1200
        				: 60 + c.getFederationMember().getSessionTimeout().intValue();
        HashSessionManager sessionManager = new HashSessionManager();
        if (!plainSocket) {
        	sessionManager.setHttpOnly(true);
        	sessionManager.setSecureCookies(true);
        }
		sessionManager.setMaxInactiveInterval(timeout); // 20 minutes timeout
        sessionManager.addEventListener(new SessionListener());
        ctx.getSessionHandler().setSessionManager(sessionManager);
        
        return ctx;
    }

	private void configureOpenidProfile(ServletContextHandler ctx, SAMLProfile openIdProfile) {
		ServletHolder servlet;
		servlet = new ServletHolder(
		        AuthorizationEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("AuthorizationEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, 
				openIdProfile.getAuthorizationEndpoint() == null ? 
						"/authorization": 
						openIdProfile.getAuthorizationEndpoint()); //$NON-NLS-1$
		ctx.addServlet(servlet, "/auth/realms/soffid/protocol/openid-connect/auth"); //$NON-NLS-1$

		
		servlet = new ServletHolder(
		        RegisterEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("RegisterEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/register"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/auth/realms/soffid/clients-registrations/default"); //$NON-NLS-1$
		
		servlet = new ServletHolder(
		        TokenEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("TokenEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, 
				openIdProfile.getTokenEndpoint() == null ? 
						"/token": 
						openIdProfile.getTokenEndpoint()); //$NON-NLS-1$
		ctx.addServlet(servlet, "/auth/realms/soffid/protocol/openid-connect/token"); //$NON-NLS-1$

		servlet = new ServletHolder(
		        TokenIntrospectionEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("TokenIntrospectionEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/token_info"); //$NON-NLS-1$

		servlet = new ServletHolder(
		        RevokeEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("RevokeEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, 
				openIdProfile.getRevokeEndpoint() == null ? 
						"/revoke": 
						openIdProfile.getRevokeEndpoint()); //$NON-NLS-1$

		servlet = new ServletHolder(
		        LogoutEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("LogoutEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, 
				openIdProfile.getLogoutEndpoint() == null ? 
						"/logout": 
						openIdProfile.getLogoutEndpoint()); //$NON-NLS-1$
		ctx.addServlet(servlet, "/auth/realms/soffid/protocol/openid-connect/logout"); //$NON-NLS-1$

		servlet = new ServletHolder(
		        UserInfoEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("UserinfoEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, 
				openIdProfile.getUserInfoEndpoint() == null ? 
						"/userinfo": 
						openIdProfile.getUserInfoEndpoint()); //$NON-NLS-1$
		ctx.addServlet(servlet, "/auth/realms/soffid/protocol/openid-connect/userinfo"); //$NON-NLS-1$

		servlet = new ServletHolder(
		        ImpersonationEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("ImpersonationEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, 
				openIdProfile.getUserInfoEndpoint() == null ? 
						"/userinfo/impersonate": 
						openIdProfile.getUserInfoEndpoint()+"/impersonate"); //$NON-NLS-1$

		servlet = new ServletHolder(
		        SessionCookieEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("SessionCookieEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, 
					"/session_cookie"); //$NON-NLS-1$

		servlet = new ServletHolder(
		        ConfigurationEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("ConfigurationEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/.well-known/openid-configuration"); //$NON-NLS-1$

		servlet = new ServletHolder(JWKEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("JWKSEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/.well-known/jwks.json"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/auth/realms/soffid/protocol/openid-connect/certs");
		
		servlet = new ServletHolder(
		        IframeSession.class);
		servlet.setInitOrder(2);
		servlet.setName("IframeSession"); //$NON-NLS-1$
		ctx.addServlet(servlet, IframeSession.URI); //$NON-NLS-1$

		servlet = new ServletHolder(
		        KeepAliveServlet.class);
		servlet.setInitOrder(2);
		servlet.setName("Keepalivesession"); //$NON-NLS-1$
		ctx.addServlet(servlet, KeepAliveServlet.URI); //$NON-NLS-1$
	}

	private void configureCasProfile(ServletContextHandler ctx, SAMLProfile openIdProfile) {
		ServletHolder servlet;
		servlet = new ServletHolder(LoginEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("cas-loginEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/cas/login"); //$NON-NLS-1$

		servlet = new ServletHolder(es.caib.seycon.idp.cas.LogoutEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("cas-logoutEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/cas/logout"); //$NON-NLS-1$

		servlet = new ServletHolder(ValidateEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("cas-validateEndpoint"); //$NON-NLS-1$
		ctx.addServlet(servlet, "/cas/validate"); //$NON-NLS-1$

		servlet = new ServletHolder(ServiceValidateEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("cas-serviceValidateEndpoint"); //$NON-NLS-1$
		servlet.setInitParameter("version", "2");
		ctx.addServlet(servlet, "/cas/serviceValidate"); //$NON-NLS-1$

		servlet = new ServletHolder(ServiceValidateEndpoint.class);
		servlet.setInitOrder(2);
		servlet.setName("cas-serviceValidateEndpoint.v3"); //$NON-NLS-1$
		servlet.setInitParameter("version", "3");
		ctx.addServlet(servlet, "/cas/p3/serviceValidate"); //$NON-NLS-1$
	}


	private void configureSamlProfile(ServletContextHandler ctx) {
		ServletHolder servlet;
		// Servlets
		servlet = new ServletHolder(
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
		servlet = new ServletHolder(MetadataServlet.class);
		servlet.setInitOrder(1);
		servlet.setName("Metadata servlet"); //$NON-NLS-1$
		ctx.addServlet(servlet, MetadataServlet.URI); //$NON-NLS-1$
	}

	private boolean needsKerberos(IdpConfig c) throws InternalErrorException {
		if (c.getFederationMember().getAuthenticationMethods() != null &&
				c.getFederationMember().getAuthenticationMethods().contains("K"))
			return true;
		
		for (FederationMember fm: c.findVirtualIdentityProviders())
		{
			if (fm.getAuthenticationMethods() != null && fm.getAuthenticationMethods().contains("K"))
				return true;
		}
		return false;
	}

	private SAMLProfile useOpenidProfile() throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
        IdpConfig c = IdpConfig.getConfig();
		FederationService federacioService = c.getFederationService();
		FederationMember fm = c.getFederationMember();
		
        Collection<SAMLProfile> profiles = federacioService
                .findProfilesByFederationMember(fm);
        for (Iterator<SAMLProfile> it = profiles.iterator(); it.hasNext();) {
            SAMLProfile profile = (SAMLProfile) it.next();
            SamlProfileEnumeration type = profile.getClasse();
            if (type.equals(SamlProfileEnumeration.OPENID) && Boolean.TRUE.equals(profile.getEnabled())) {
            	return profile;
            }
        }
        return null;
	}

	private SAMLProfile useCasProfile() throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
        IdpConfig c = IdpConfig.getConfig();
		FederationService federacioService = c.getFederationService();
		FederationMember fm = c.getFederationMember();
		
        Collection<SAMLProfile> profiles = federacioService
                .findProfilesByFederationMember(fm);
        for (Iterator<SAMLProfile> it = profiles.iterator(); it.hasNext();) {
            SAMLProfile profile = (SAMLProfile) it.next();
            SamlProfileEnumeration type = profile.getClasse();
            if (type.equals(SamlProfileEnumeration.OPENID) && Boolean.TRUE.equals(profile.getEnabled())) {
            	return profile;
            }
        }
        return null;
	}

	private SAMLProfile useRadiusProfile() throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
        IdpConfig c = IdpConfig.getConfig();
		FederationService federacioService = c.getFederationService();
		FederationMember fm = c.getFederationMember();
		
        Collection<SAMLProfile> profiles = federacioService
                .findProfilesByFederationMember(fm);
        for (Iterator<SAMLProfile> it = profiles.iterator(); it.hasNext();) {
            SAMLProfile profile = (SAMLProfile) it.next();
            SamlProfileEnumeration type = profile.getClasse();
            if (type.equals(SamlProfileEnumeration.RADIUS)  && Boolean.TRUE.equals(profile.getEnabled())) {
            	return profile;
            }
        }
        return null;
	}

	private SAMLProfile useTacacsProfile() throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
        IdpConfig c = IdpConfig.getConfig();
		FederationService federacioService = c.getFederationService();
		FederationMember fm = c.getFederationMember();
		
        Collection<SAMLProfile> profiles = federacioService
                .findProfilesByFederationMember(fm);
        for (Iterator<SAMLProfile> it = profiles.iterator(); it.hasNext();) {
            SAMLProfile profile = (SAMLProfile) it.next();
            SamlProfileEnumeration type = profile.getClasse();
            if (type.equals(SamlProfileEnumeration.TACACS_PLUS)  && Boolean.TRUE.equals(profile.getEnabled())) {
            	return profile;
            }
        }
        return null;
	}

	private boolean useSamldProfile() throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
        IdpConfig c = IdpConfig.getConfig();
		FederationService federacioService = c.getFederationService();
		FederationMember fm = c.getFederationMember();
		
        Collection<SAMLProfile> profiles = federacioService
                .findProfilesByFederationMember(fm);
        for (Iterator<SAMLProfile> it = profiles.iterator(); it.hasNext();) {
            SAMLProfile profile = (SAMLProfile) it.next();
            SamlProfileEnumeration type = profile.getClasse();
            if (type.equals(SamlProfileEnumeration.SAML1_AR) || 
            		type.equals(SamlProfileEnumeration.SAML2_AR) || 
            		type.equals(SamlProfileEnumeration.SAML1_AQ) ||
            		type.equals(SamlProfileEnumeration.SAML2_SSO) || 
            		type.equals(SamlProfileEnumeration.SAML2_ECP)) {
            	return true;
            }
        }
        return false;
	}

	private void configureSpnego(ServletContextHandler ctx, IdpConfig c) throws FileNotFoundException,
			IOException, NoSuchAlgorithmException, LoginException {
		File f = new File (c.getConfDir(), "krb5.keytab");
		Constraint constraint = new Constraint(Constraint.__SPNEGO_AUTH, "Soffid Identity Provider");
		if (f.canRead())
			constraint.setRoles(new String[] { c.getFederationMember().getKerberosDomain(),
        		c.getFederationMember().getKerberosDomain().toLowerCase(),
        		c.getFederationMember().getKerberosDomain().toUpperCase()
        		});
		else
		{
			Set<String> domains = new HashSet<String>();
			for ( KerberosKeytab domain: c.getFederationMember().getKeytabs())
			{
				domains.add (domain.getDomain());
				domains.add (domain.getDomain().toLowerCase());
				domains.add (domain.getDomain().toUpperCase());
			}
			constraint.setRoles( domains.toArray(new String[0]));
		}
        constraint.setAuthenticate(true);
        
        ConstraintMapping constraintMapping = new ConstraintMapping();
        constraintMapping.setConstraint(constraint);
        constraintMapping.setPathSpec(NtlmAction.URI);

        ConstraintSecurityHandler csh = new ConstraintSecurityHandler();
        LoginService loginService;
        if (f.canRead() && c.getFederationMember().getKeytabs().isEmpty())
        {
        	loginService = new SpnegoLoginService("SpnegoLogin", new File(c.getConfDir(), "spnego.properties").toString());
        }
        else
        {
        	loginService = new CustomSpnegoLoginService("CustomSpnegoLogin");
        }
        csh.setAuthenticator(new SpnegoAuthenticator());
        csh.setRealmName("Soffid");
        csh.setConstraintMappings(new ConstraintMapping[] {constraintMapping});
        csh.setLoginService( loginService );
        
        ctx.setSecurityHandler(csh);
        
        ctx.addServlet(NtlmAction.class, NtlmAction.URI);
        // Now perform login
        Configuration cfg = Configuration.getInstance("JavaLoginConfig", new URIParameter(new File (c.getConfDir(), "spnego.conf").toURI()));
        ChainConfiguration.addConfiguration(cfg);
	}
}
