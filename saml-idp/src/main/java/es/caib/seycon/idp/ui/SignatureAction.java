package es.caib.seycon.idp.ui;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.server.session.JDBCSessionManager.Session;
import org.opensaml.saml2.core.AuthnContext;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import es.caib.seycon.InternalErrorException;
import es.caib.seycon.InvalidPasswordException;
import es.caib.seycon.Password;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.signatura.api.Signature;
import es.caib.signatura.api.SignatureProviderException;
import es.caib.signatura.api.SignatureVerifyException;

public class SignatureAction extends HttpServlet {
    LogRecorder logRecorder = LogRecorder.getInstance();

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/signatureLoginAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String p = req.getParameter("j_password"); //$NON-NLS-1$
        String error = null;
        try {
            Signature sig = getSignature(p);
            HttpSession session = req.getSession();

            String challenge = (java.lang.String) session
                    .getAttribute("seu.challenge"); //$NON-NLS-1$
            ByteArrayInputStream in = new ByteArrayInputStream(
                    challenge.getBytes("UTF-8")); //$NON-NLS-1$
            
            
            CertificateValidator v = new CertificateValidator();
            try {
                String certUser = v.validate(sig.getCertificateChain());
                if (certUser != null) {
                    if (!sig.verify(in)) {
                        logRecorder.addErrorLogEntry(certUser, Messages.getString("SignatureAction.4"), req.getRemoteAddr()); //$NON-NLS-1$
                        throw new InvalidPasswordException(Messages.getString("SignatureAction.tamperedSignature")); //$NON-NLS-1$
                    }
                    if (!sig.verify()) {
                        logRecorder.addErrorLogEntry(certUser, Messages.getString("SignatureAction.invalidCertificate"), req.getRemoteAddr()); //$NON-NLS-1$
                        throw new InvalidPasswordException(Messages.getString("SignatureAction.unrecognizedCertificate")); //$NON-NLS-1$
                    }
                    new Autenticator().autenticate(certUser, req, resp, AuthnContext.X509_AUTHN_CTX, true);
                } else {
                    logRecorder.addErrorLogEntry(certUser, Messages.getString("SignatureAction.unableToReadCertificate")+sig.getCertSubjectCommonName(),  //$NON-NLS-1$
                            req.getRemoteAddr());
                    error = Messages.getString("SignatureAction.unableToGuessUserName"); //$NON-NLS-1$
                }
            } catch (InternalErrorException e) {
                error = Messages.getString("SignatureAction.unableToCreateUser")+e.toString(); //$NON-NLS-1$
                log(Messages.getString("SignatureAction.UnexpectedError"), e); //$NON-NLS-1$
            } catch (UnknownUserException e) {
                error = Messages.getString("SignatureAction.unableToGuetUserForCertificate")+e.toString(); //$NON-NLS-1$
                log(Messages.getString("SignatureAction.UnexpectedError"), e); //$NON-NLS-1$
            } catch (SignatureProviderException e) {
                log(Messages.getString("SignatureAction.UnexpectedError"), e); //$NON-NLS-1$
                error = Messages.getString("SignatureAction.InternalError")+e.toString(); //$NON-NLS-1$
            } catch (SignatureVerifyException e) {
                log(Messages.getString("SignatureAction.16"), e); //$NON-NLS-1$
                error = Messages.getString("SignatureAction.17"); //$NON-NLS-1$
            } catch (Exception e) {
                error = Messages.getString("SignatureAction.18")+e.toString(); //$NON-NLS-1$
                log(Messages.getString("SignatureAction.19"), e); //$NON-NLS-1$
            }

        } catch (InvalidPasswordException e) {
            error = e.getMessage();
        }

        req.setAttribute(Messages.getString("SignatureAction.20"), error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req
                .getRequestDispatcher(SignatureForm.URI);
        dispatcher.forward(req, resp);
    }

    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        
        doPost(req, resp);
    }


    private Signature getSignature(String pass) throws IOException,
            InvalidPasswordException {
        byte b[] = new byte[pass.length() / 2];
        for (int i = 0, j = 0; i < pass.length();) {
            int c = getHexValue(pass.charAt(i++)) * 16;
            c = c + getHexValue(pass.charAt(i++));
            b[j++] = (byte) c;
        }
        ByteArrayInputStream in = new ByteArrayInputStream(b);
        ObjectInputStream objIn = new ObjectInputStream(in);
        Signature signature = null;
        try {
            signature = (Signature) objIn.readObject();
        } catch (Exception e) {
            throw new InvalidPasswordException(
                    Messages.getString("SignatureAction.21")); //$NON-NLS-1$
        }
        objIn.close();
        in.close();
        return signature;

    }

    private int getHexValue(char c) {
        if (c >= '0' && c <= '9')
            return (int) c - (int) '0';
        if (c >= 'A' && c <= 'F')
            return (int) c - (int) 'A' + 10;
        if (c >= 'a' && c <= 'f')
            return (int) c - (int) 'a' + 10;
        throw new RuntimeException(Messages.getString("SignatureAction.22") + c); //$NON-NLS-1$
    }

}
