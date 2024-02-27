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
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.sync.service.ServerService;
import com.soffid.iam.utils.Security;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.shibext.LogRecorder;
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
    			if (accounts == null || accounts.isEmpty()) {
    				LogRecorder.getInstance().addErrorLogEntry(
    						getProtocol(member), user, 
    						"Access denied to "+member.getPublicId(),
    						null, 
    						Security.getClientIp()); 
    				return false;
    			}
    		}
    		if (member.getRoles() != null && !member.getRoles().isEmpty()) {
    			boolean found = false;
    			for (RoleGrant role: new RemoteServiceLocator().getServerService().getUserRoles(ui.getId(), null)) {
    				if (member.getRoles().contains(role.getRoleName()+"@"+role.getSystem())) {
    					found = true;
    					break;
    				}
    			}
    			if (!found) {
    				LogRecorder.getInstance().addErrorLogEntry(
    						getProtocol(member), user, 
    						"Access denied to "+member.getPublicId(),
    						null, 
    						Security.getClientIp()); 
    				return false;
    			}
    		}
    	}
    	return true;

	}

	private String getProtocol(FederationMember member) {
		return member.getServiceProviderType() == ServiceProviderType.CAS ? "CAS":
			member.getServiceProviderType() == ServiceProviderType.OPENID_CONNECT ? "OPENID":
			member.getServiceProviderType() == ServiceProviderType.OPENID_REGISTER ? "OPENID":
			member.getServiceProviderType() == ServiceProviderType.RADIUS ? "RADIUS":
			member.getServiceProviderType() == ServiceProviderType.SOFFID_SAML ? "SAML":
			member.getServiceProviderType() == ServiceProviderType.SAML ? "SAML":
			member.getServiceProviderType() == ServiceProviderType.TACACSP ? "TACACS+":
			member.getServiceProviderType() == ServiceProviderType.WS_FEDERATION ? "WSFED":
			"SAML";
	}
}
