package es.caib.seycon.idp.shibext;

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.LinkedList;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.sync.service.ServerService;

public class RolesDelayedAttribute extends DelayedAttribute
{

	private ServerService serverService;
	private Account account;
	private User user;
	public RolesDelayedAttribute(String name, Attribute att, ServerService service, User user, Account account) {
		super(name, null, null, att);
		this.serverService = service;
		this.account = account;
		this.user =  user;
	}

	protected Collection<String> doResolve() {
		try {
	        Collection<RoleGrant> roles = user == null ?
	        		serverService.getAccountRoles(account.getName(), account.getSystem()) :
	        		serverService.getUserRoles(user.getId(), null);
	        LinkedList<String> l = new LinkedList<String>();
	        for (RoleGrant role : roles) {
	            String v = role.getRoleName();
	            if (role.getDomainValue() != null && role.getDomainValue().length() > 0)
	                v += "/" + role.getDomainValue(); //$NON-NLS-1$
	            v += "@"+role.getSystem(); //$NON-NLS-1$
	            l.add(v);
	        }
	        array = true;
	        return l;
		} catch (Exception e) {
			throw new RuntimeException("Error fitching memberOf", e);
		}
		
        
    }

}
