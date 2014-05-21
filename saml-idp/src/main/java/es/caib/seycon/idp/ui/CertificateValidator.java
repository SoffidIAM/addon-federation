package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.servei.ServerService;

public class CertificateValidator {
    public String validate(HttpServletRequest req) throws InternalErrorException, IOException, UnknownUserException {
        X509Certificate certs[] = (X509Certificate[]) req
                .getAttribute("javax.servlet.request.X509Certificate"); //$NON-NLS-1$
        return validate (certs);

    }

    public String validate(X509Certificate certs[]) throws InternalErrorException, IOException, UnknownUserException {
        if (certs == null || certs.length == 0) {
            return null;
        } else {
        	ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
            Usuari ui = server.getUserInfo(certs);
            return ui.getCodi();
        }

    }
}
