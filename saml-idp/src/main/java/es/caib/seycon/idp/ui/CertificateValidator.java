package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
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
            if (ui == null)
            	return null;

            IdpConfig cfg;
    		try {
    			cfg = IdpConfig.getConfig();
    		} catch (Exception e) {
    			throw new InternalErrorException("Error getting default dispatcher", e);
    		}
    		for (UserAccount account: server.getUserAccounts(ui.getId(), cfg.getSystem().getName())) {
    			if (!account.isDisabled()) {
    				return account.getName();
    			}
    			else
    				LogFactory.getLog(getClass()).warn("User "+ui.getUserName()+" cannot login because account "+account.getName()+" is not enabled");
    		}
    		return null;
        }

    }
}
