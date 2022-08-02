package es.caib.seycon.idp.server;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class AuthorizationHandler {
	static Log log = LogFactory.getLog(AuthorizationHandler.class);
	
	public boolean checkAuthorization(String user, FederationMember member) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, UnknownUserException {
    	ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
    	final String systemName = IdpConfig.getConfig().getSystem().getName();
    	log.info("Getting information of "+user+" at "+systemName);
		User ui = server.getUserInfo(user, systemName);

    	if (member != null)
    	{
    		if (member.getSystem() != null) {
    			Collection<UserAccount> accounts = new RemoteServiceLocator().getServerService().getUserAccounts(ui.getId(), member.getSystem());
    			if (accounts == null || accounts.isEmpty())
    				throw new SecurityException("Access denied");
    		}
    		if (member.getRoles() != null && !member.getRoles().isEmpty()) {
    			boolean found = false;
    			for (RoleGrant role: new RemoteServiceLocator().getServerService().getUserRoles(ui.getId(), null)) {
    				if (member.getRoles().contains(role.getRoleName()+"@"+role.getSystem())) {
    					found = true;
    					break;
    				}
    			}
    			if (!found)
    				return false;
    		}
    	}
    	return true;

	}
}
