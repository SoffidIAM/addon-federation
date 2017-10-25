package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import com.soffid.iam.api.User;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

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
        	com.soffid.iam.sync.service.ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
            User ui = server.getUserInfo(certs);
            return ui.getUserName();
        }

    }
}
