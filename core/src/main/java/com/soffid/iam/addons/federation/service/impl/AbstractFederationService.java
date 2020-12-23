package com.soffid.iam.addons.federation.service.impl;

import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.Assertion;

import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.model.FederationMemberEntityDao;
import com.soffid.iam.addons.federation.model.IdentityProviderEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderEntity;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.api.User;
import com.soffid.iam.model.SamlRequestEntityDao;
import com.soffid.iam.service.AccountService;
import com.soffid.iam.service.AdditionalDataService;
import com.soffid.iam.service.ConfigurationService;
import com.soffid.iam.service.DispatcherService;
import com.soffid.iam.service.PasswordService;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.service.UserDomainService;
import com.soffid.iam.service.UserService;

import es.caib.seycon.ng.exception.InternalErrorException;

public abstract class AbstractFederationService {
	Log log = LogFactory.getLog(getClass());

	private ConfigurationService configurationService;

	protected FederationMemberEntityDao federationMemberEntityDao;
	protected SamlRequestEntityDao samlRequestEntityDao;
	protected UserDomainService userDomainService;
	protected SessionService sessionService;
	protected AdditionalDataService additionalData;
	protected AccountService accountService;
	protected UserService userService;
	protected DispatcherService dispatcherService;
	private PasswordService passwordService;
	private FederationServiceInternal serviceBase;

	public AbstractFederationService () {
	}
	
	public void setFederationServiceInternal (FederationServiceInternal serviceBase)  {
		this.serviceBase = serviceBase;
	}

	public void setConfigurationService(ConfigurationService configurationService) {
		this.configurationService = configurationService;
	}

	public void setFederationMemberEntityDao(FederationMemberEntityDao federationMemberEntityDao) {
		this.federationMemberEntityDao = federationMemberEntityDao;
	}

	public void setSamlRequestEntityDao(SamlRequestEntityDao samlRequestEntityDao) {
		this.samlRequestEntityDao = samlRequestEntityDao;
	}

	public void setUserDomainService(UserDomainService userDomainService) {
		this.userDomainService = userDomainService;
	}

	public void setSessionService(SessionService sessionService) {
		this.sessionService = sessionService;
	}

	public void setAdditionalData(AdditionalDataService additionalData) {
		this.additionalData = additionalData;
	}

	public void setAccountService(AccountService accountService) {
		this.accountService = accountService;
	}

	public void setUserService(UserService userService) {
		this.userService = userService;
	}

	public void setDispatcherService(DispatcherService dispatcherService) {
		this.dispatcherService = dispatcherService;
	}

	public void setPasswordService(PasswordService passwordService) {
		this.passwordService = passwordService;
	}

	public SamlValidationResults authenticate(String serviceProviderName, String protocol, Map<String, String> response,
			boolean autoProvision) throws Exception {
		return serviceBase.authenticate(serviceProviderName, protocol, response, autoProvision);
	}

	public SamlRequest generateRequest(String serviceProvider, String identityProvider, String userName,
			long sessionSeconds) throws InternalErrorException {
		return serviceBase.generateRequest(serviceProvider, identityProvider, userName, sessionSeconds);
	}

	public SamlRequest generateLogout(String serviceProvider, String identityProvider, String userName, boolean forced,
			boolean backChannel) throws InternalErrorException {
		return serviceBase.generateLogout(serviceProvider, identityProvider, userName, forced, backChannel);
	}

	public SamlValidationResults authenticate(String serviceProvider, String identityProvider, String user,
			String password, long sessionSeconds)
			throws InternalErrorException, RemoteException, NoSuchAlgorithmException {
		return serviceBase.authenticate(serviceProvider, identityProvider, user, password, sessionSeconds);
	}

	public User findAccountOwner(String principalName, String identityProvider, Map<String, ? extends Object> map,
			boolean autoProvision) throws Exception {
		return serviceBase.findAccountOwner(principalName, identityProvider, map, autoProvision);
	}

	public void expireSessionCookie(String cookie)
			throws InternalErrorException, UnsupportedEncodingException, NoSuchAlgorithmException {
		serviceBase.expireSessionCookie(cookie);
	}

	public String generateRandomId() throws NoSuchAlgorithmException {
		return serviceBase.generateRandomId();
	}

	public IdentityProviderEntity findIdentityProvider(String identityProvider) {
		return serviceBase.findIdentityProvider(identityProvider);
	}

	public ServiceProviderEntity findServiceProvider(String identityProvider) {
		return serviceBase.findServiceProvider(identityProvider);
	}

}
