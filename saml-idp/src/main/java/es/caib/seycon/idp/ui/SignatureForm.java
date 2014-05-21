package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URLEncoder;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.util.storage.StorageService;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.InternalErrorException;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.idp.textformatter.TextFormatter;

public class SignatureForm extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/signatureLoginForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);

        try {
            HttpSession session = req.getSession();
            
            String challenge = (String) session.getAttribute("seu.challenge"); //$NON-NLS-1$
            if (challenge == null) {
                StringBuffer c = new StringBuffer(32);
                SecureRandom r = new SecureRandom();
                for (int i = 0; i < 32; i++) {
                    int ch = r.nextInt();
                    ch = ch % 95;
                    if (ch < 0) ch += 95;
                    ch += 32;
                    c.append((char) ch);
                }
                challenge = c.toString();
                session.setAttribute("seu.challenge", challenge);                 //$NON-NLS-1$
            }
            
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.addArgument("login.certificado.challenge", challenge); //$NON-NLS-1$
            g.generate(resp, "loginPage_APPLET.html"); //$NON-NLS-1$
        } catch (TextFormatException e) {
            throw new ServletException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    

}
