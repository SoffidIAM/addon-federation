package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.LinkedList;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.User;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.service.SyncServerService;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.service.SecretStoreService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SecretsDelayedAttribute extends DelayedAttribute{

	private User user;

	public SecretsDelayedAttribute(String name, User user, Attribute att) {
		super(name, null, null, att);
		this.user = user;
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

	public String generateSecrets() throws IOException, InternalErrorException 
	{
        StringBuffer result = new StringBuffer();
        SecretStoreService sss = new RemoteServiceLocator().getSecretStoreService();
        for (Secret secret : sss.getAllSecrets(user)) {
        	if (secret.getName() != null && secret.getName().length() > 0 &&
        			secret.getValue() != null &&
        			secret.getValue().getPassword() != null &&
        			secret.getValue().getPassword().length() > 0 )
        	{
        		if (result.length() > 0)
        			result.append('|');
               	result.append( encodeSecret(secret.getName()));
                result.append('|');
                result.append( encodeSecret(secret.getValue().getPassword()));
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
