package com.soffid.iam.addons.federation.service.impl;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import org.apache.commons.beanutils.PropertyUtils;
import org.jbpm.JbpmContext;
import org.jbpm.graph.def.ProcessDefinition;
import org.jbpm.graph.exe.ExecutionContext;
import org.jbpm.graph.exe.ProcessInstance;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.FederationMemberEntityDao;
import com.soffid.iam.addons.federation.model.IdentityProviderEntity;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.User;
import com.soffid.iam.bpm.service.BpmEngine;
import com.soffid.iam.service.UserService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class WorkflowInitiator {
	FederationMemberEntityDao federationMemberEntityDao;
	BpmEngine bpmEngine;
	UserService userService = ServiceLocator.instance().getUserService();
	private Password password;
	
	public boolean startWF(String identityProvider, User user, Map additionalData) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException, InternalErrorException {
		String org = "";
		boolean started = false;
		for (FederationMemberEntity fm: getFederationMemberEntityDao().findFMByPublicId(identityProvider)) {
			if (fm instanceof IdentityProviderEntity) {
				IdentityProviderEntity idp = (IdentityProviderEntity) fm;
				if (idp.getRegisterWorkflow() != null &&
						! idp.getRegisterWorkflow().trim().isEmpty()) {
					startWF(user, additionalData, idp.getRegisterWorkflow());
					started = true;
					User u = userService.findUserByUserName(user.getUserName());
					if (u != null)
					{
						PropertyUtils.copyProperties(user, u);
					} else {
						user.setActive(false);
					}
				}
			}
		}
		return started;

	}

	private void startWF(User user, Map additionalData, String processDefinition) throws InternalErrorException, IllegalAccessException, InvocationTargetException, NoSuchMethodException {
		JbpmContext ctx = getBpmEngine().getContext();
		try {
			ProcessDefinition def = ctx.getGraphSession().findLatestProcessDefinition(processDefinition);
			if (def == null)
				throw new InternalErrorException("Internal error: Cannot find process "+processDefinition);
			ProcessInstance pi = def.createProcessInstance();
			ExecutionContext ec = new ExecutionContext(pi.getRootToken());
			Map m = PropertyUtils.describe(user);
			for ( Object key: m.keySet()) {
				if (!key.equals("attributes"))
					ec.setVariable(key.toString(), m.get(key));
			}
			for ( Object key: additionalData.keySet()) {
				ec.setVariable(key.toString(), additionalData.get(key));
			}
			if (password != null)
				ec.setVariable("password", password);
			pi.signal();
			ctx.save(pi);
		} finally {
			ctx.close();
		}
	}

	public FederationMemberEntityDao getFederationMemberEntityDao() {
		return federationMemberEntityDao;
	}

	public void setFederationMemberEntityDao(FederationMemberEntityDao federationMemberEntityDao) {
		this.federationMemberEntityDao = federationMemberEntityDao;
	}

	public BpmEngine getBpmEngine() {
		return bpmEngine;
	}

	public void setBpmEngine(BpmEngine bpmEngine) {
		this.bpmEngine = bpmEngine;
	}

	public void setPassword(Password password) {
		this.password = password;
	}

}
