package es.caib.seycon.idp.shibext;

import java.util.Collection;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.Audit;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ValueObjectMapper;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.service.ServerService;
import com.soffid.iam.utils.Security;

import es.caib.seycon.idp.config.IdpConfig;

public class UidEvaluator {
    public String evaluateUid(ServerService server, String rpid, String principal, User ui) throws Exception {
    	String uid = ui == null ? principal : ui.getUserName();
    	FederationService fs = new RemoteServiceLocator().getFederacioService();
    	FederationMember member = fs.findFederationMemberByPublicId(rpid);
    	if (member != null) {
    		if (member.getSystem() != null) {
    			Collection<UserAccount> accounts = new RemoteServiceLocator().getServerService().getUserAccounts(ui.getId(), member.getSystem());
    			if (accounts == null || accounts.isEmpty()) {
    				return null;
    			}
    		}
    		if (member.getUidExpression() != null && ! member.getUidExpression().trim().isEmpty())
    		{
            	IdpConfig config = IdpConfig.getConfig();
    			Account account = server.getAccountInfo(principal, config.getSystem().getName());
    			ExtensibleObject eo = ui == null ? 
    				new AccountExtensibleObject(account, server):
    				new UserExtensibleObject(account, ui, server);
    			eo.setAttribute("relyingParty", rpid);
   				uid = (String) new ObjectTranslator(config.getSystem(), server,
    					new java.util.LinkedList<ExtensibleObjectMapping>())
    						.eval(member.getUidExpression(), eo);
    		}
    	}
    	return uid;
    	
	}

}
