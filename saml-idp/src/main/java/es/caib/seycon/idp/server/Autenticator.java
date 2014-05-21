package es.caib.seycon.idp.server;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.federation.idp.LanguageFilter;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.session.SessionCallbackServlet;
import es.caib.seycon.idp.session.SessionListener;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.shibext.SessionPrincipal;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.comu.Sessio;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.servei.ServerService;
import es.caib.seycon.ssl.SeyconKeyStore;
import es.caib.seycon.util.Base64;

public class Autenticator {
    private static final Logger LOG = LoggerFactory.getLogger(Autenticator.class);

    private String generateSession (HttpSession session, String principal, boolean externalAuth) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, UnknownUserException
    {
        ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        
        IdpConfig config = IdpConfig.getConfig();
        
        Usuari user = server.getUserInfo(principal, config.getDispatcher().getCodi());
        
        server.updateExpiredPasswords(user, externalAuth);
        
        String url = "https://" + config.getHostName()+":"+config.getStandardPort()+ SessionCallbackServlet.URI;
        
        Sessio sessio = new RemoteServiceLocator().getSessioService().registraSessioWeb(
        		user.getCodi(), config.getHostName(),
        		LanguageFilter.getRemoteIp(),
        		url);

        SessionListener.registerSession(session, sessio.getId().toString());
        
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(SeyconKeyStore.getKeyStoreFile()),
        		SeyconKeyStore.getKeyStorePassword().getPassword().toCharArray());

        Certificate cert = ks.getCertificate(SeyconKeyStore.ROOT_CERT);
        String certString = Base64.encodeBytes(cert.getEncoded());
        
        Config serverConfig = Config.getConfig();

        StringBuffer buffer = new StringBuffer ();
        buffer.append (sessio.getId()).append("|").append(sessio.getClau()).
        	append("|").
        	append (certString).append("|").
        	append(serverConfig.getServerList());
        
        return buffer.toString();
    }
    
    public void autenticate (String user, HttpServletRequest req, HttpServletResponse resp, String type, boolean externalAuth) throws IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException {
    	autenticate(user, req, resp, type, type, externalAuth);
    }
    
    public void autenticate (String user, HttpServletRequest req, HttpServletResponse resp, String type, String actualType, boolean externalAuth) throws IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException {

        LOG.info("Remote user identified as "+user+". returning control back to authentication engine"); //$NON-NLS-1$ //$NON-NLS-2$

        HttpSession session = req.getSession();
        session.setAttribute(SessionConstants.SEU_USER, user);
        
        String returnPath = (String) session.getAttribute(SessionConstants.AUTHENTICATION_REDIRECT);
        String entityId = (String) session
                .getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);

        Principal principal = new SessionPrincipal(user, generateSession(req.getSession(), user, externalAuth));
        
        req.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
        req.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, type);
        req.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, user);
        Set<Principal> principals = new HashSet<Principal> ();
        Set<?> pubCredentals = new HashSet<Object>();
        Set<?> privCredentials = new HashSet<Object>();
        principals.add(principal);
        Subject userSubject = new Subject(false,principals, pubCredentals, privCredentials); 
        req.setAttribute(LoginHandler.SUBJECT_KEY, userSubject);
        
        LogRecorder.getInstance().addSuccessLogEntry(user, actualType, entityId, req.getRemoteAddr(), req.getSession());
        
        if (returnPath == null) 
        {
            AuthenticationEngine.returnToAuthenticationEngine(req, resp);
        }
        else
        {
            resp.sendRedirect(returnPath);
        }
    }

}
