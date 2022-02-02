package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.LinkedList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.User;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.service.SyncServerService;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.service.SecretStoreService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class SecretsDelayedAttribute extends DelayedAttribute{
	static Log log = LogFactory.getLog(SecretsDelayedAttribute.class);
	private User user;
	private String serviceProvider;

	public SecretsDelayedAttribute(String name, User user, Attribute att, String serviceProvider) {
		super(name, null, null, att);
		this.user = user;
		this.serviceProvider = serviceProvider;
	}

	@Override
	protected Collection<String> doResolve() {
		LinkedList<String> l = new LinkedList<>();
		try {
			l.add(generateSecrets());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return l;
	}

	public String generateSecrets() throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException 
	{
		log.info("Generating secrets for relying party "+serviceProvider);
		String system = null;
		FederationMember fm = IdpConfig.getConfig().getFederationService().findFederationMemberByPublicId(serviceProvider);
		if (fm != null)
			system = fm.getSystem();
		log.info("Filter out accounts of system "+system);
        StringBuffer result = new StringBuffer();
        SecretStoreService sss = new RemoteServiceLocator().getSecretStoreService();
        for (Secret secret : sss.getAllSecrets(user)) {
        	if (secret.getName() != null && secret.getName().length() > 0 &&
        			secret.getValue() != null &&
        			secret.getValue().getPassword() != null &&
        			secret.getValue().getPassword().length() > 0 )
        	{
        		if (system == null || (
        				secret.getName().startsWith("sso."+system+".") || 
        				secret.getName().startsWith("account."+system+".") || 
        				secret.getName().equals("account."+system) || 
        				secret.getName().startsWith("accdesc."+system+".") || 
        				secret.getName().startsWith("pass."+system+".") || 
        				secret.getName().startsWith("user") ))  {
	        		if (result.length() > 0)
	        			result.append('|');
	               	result.append( encodeSecret(secret.getName()));
	                result.append('|');
	                result.append( encodeSecret(secret.getValue().getPassword()));
        		}
        	}
        }
        result.append ("|sessionKey|");
       	result.append ("|fullName|").append(encodeSecret(user.getFullName()));
        return result.toString();
    }



	private String encodeSecret(String secret)
			throws UnsupportedEncodingException {
		return secret.replace("\\", "\\\\").replace("|", "\\|"); 
	}
}
