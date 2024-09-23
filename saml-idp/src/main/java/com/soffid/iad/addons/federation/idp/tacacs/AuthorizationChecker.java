package com.soffid.iad.addons.federation.idp.tacacs;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.TacacsPlusAuthRule;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.interp.Evaluator;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class AuthorizationChecker {

	public boolean validate(AuthorRequest p, TacacsReader tacacs, List<Argument> arguments) throws InternalErrorException, IOException, Exception {
		FederationMember sp = tacacs.getServiceProvider();
		String user = p.user;
		
		final ServerService serverService = new RemoteServiceLocator().getServerService();
		Account account = serverService.getAccountInfo(user, 
				tacacs.getServiceProvider().getSystem());
		ExtensibleObject eo = null;
		if (account.getType() == AccountType.USER) {
			User ui = serverService.getUserInfo(account.getName(), account.getSystem());
			eo = new UserExtensibleObject(account, ui, serverService);
		} else {
			eo = new AccountExtensibleObject(account, serverService);
		}
		
		Map<String,Object> vars = new HashMap<>();
		Map<String, String> mandatoryArguments = new HashMap<>();
		Map<String, String> optionalArguments = new HashMap<>();
		vars.put("mandatoryArguments", mandatoryArguments);
		vars.put("optionalArguments", optionalArguments);
		for (Argument arg: p.arguments) {
			if (arg.isOptional)
				optionalArguments.put(arg.attribute, arg.value);
			else
				mandatoryArguments.put(arg.attribute, arg.value);
		}
		
		vars.put("priv_level", p.priv_lvl);
		vars.put("port", p.port);
		vars.put("service", p.authen_service);
		vars.put("remote_address", p.rem_addr);
		vars.put("user", eo);
		
		final List<TacacsPlusAuthRule> rules = new RemoteServiceLocator().getFederacioService().findTacacsPlusAuthRulesByServiceProvider(sp.getPublicId());
		for (TacacsPlusAuthRule rule: rules)
		{
			Object b = Evaluator.instance().evaluate(rule.getExpression(), vars, "Rule "+rule.getName());
			if (Boolean.TRUE.equals(b)) {
				for (Map.Entry<String,String> entry: mandatoryArguments.entrySet()) {
					arguments.add(new Argument(entry.getKey(), entry.getValue(), false));
				}
				for (Map.Entry<String,String> entry: optionalArguments.entrySet()) {
					arguments.add(new Argument(entry.getKey(), entry.getValue(), true));
				}
				return true;
			}
		}
		return false;
	}
	
	public boolean hasSecurityLevel(int securityLevel, String user, String system) throws InternalErrorException, IOException {
		Collection<RoleGrant> grants = fetchGrants(user, system);
		for (RoleGrant grant: grants) {
			if (grant.getSystem().equals(system)) {
				for (int i = securityLevel; i < 16; i++)
					if (grant.getRoleName().equals("TAC_PLUS_PRV_LVL_"+i))
						return true;
				if (grant.getRoleName().equals("TAC_PLUS_PRIV_LVL_ROOT"))
					return true;
				if (grant.getRoleName().equals("TAC_PLUS_PRIV_LVL_MIN") && securityLevel == 0)
					return true;
				if (grant.getRoleName().equals("TAC_PLUS_PRIV_LVL_USER") && securityLevel <= 1)
					return true;
			}
		}
		return false;
	}

	private Collection<RoleGrant> fetchGrants(String user, String system) throws InternalErrorException, IOException {
		ServerService srv = new RemoteServiceLocator().getServerService();
		try {
			User u = srv.getUserInfo(user, system);
			return srv.getUserRoles(u.getId(), null);
		} catch (UnknownUserException e) {
			return srv.getAccountRoles(user, system);
		}
				
	}

}
