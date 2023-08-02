package com.soffid.iam.addons.federation.service.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.InitializationException;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.FederationMemberEntityDao;
import com.soffid.iam.addons.federation.model.IdentityProviderEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderEntity;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.MetadataScope;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.PasswordDomain;
import com.soffid.iam.api.PasswordPolicy;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserData;
import com.soffid.iam.api.UserType;
import com.soffid.iam.bpm.service.BpmEngine;
import com.soffid.iam.model.SamlRequestEntity;
import com.soffid.iam.model.SamlRequestEntityDao;
import com.soffid.iam.service.AccountService;
import com.soffid.iam.service.AdditionalDataService;
import com.soffid.iam.service.ConfigurationService;
import com.soffid.iam.service.DispatcherService;
import com.soffid.iam.service.PasswordService;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.service.UserDomainService;
import com.soffid.iam.service.UserService;

import bsh.EvalError;
import bsh.Interpreter;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.exception.AccountAlreadyExistsException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.NeedsAccountNameException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.util.Base64;

public class FederationServiceInternal {
	SAMLServiceInternal samlService = new SAMLServiceInternal();
	OIDCServiceInternal oidcService = new OIDCServiceInternal();
	
	private static final String EXTERNAL_SAML_PASSWORD_DOMAIN = "EXTERNAL-SAML";
	private static final String ES_CAIB_SEYCON_IDP_AGENT_IDP_AGENT = "es.caib.seycon.idp.agent.IDPAgent";
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
	protected BpmEngine bpmEngine;
	private PasswordService passwordService;

	public FederationServiceInternal () throws InitializationException {
		samlService.setFederationServiceInternal(this);
		oidcService.setFederationServiceInternal(this);
	}

	public void setConfigurationService(ConfigurationService configurationService) {
		this.configurationService = configurationService;
		samlService.setConfigurationService(configurationService);
		oidcService.setConfigurationService(configurationService);
	}

	public void setFederationMemberEntityDao(FederationMemberEntityDao federationMemberEntityDao) {
		this.federationMemberEntityDao = federationMemberEntityDao;
		samlService.setFederationMemberEntityDao(federationMemberEntityDao);
		oidcService.setFederationMemberEntityDao(federationMemberEntityDao);
	}

	
	public void setSamlRequestEntityDao(SamlRequestEntityDao samlRequestEntityDao) {
		this.samlRequestEntityDao = samlRequestEntityDao;
		samlService.setSamlRequestEntityDao(samlRequestEntityDao);
		oidcService.setSamlRequestEntityDao(samlRequestEntityDao);
	}
	
	public UserService getUserService() {
		return userService;
	}

	public void setUserService(UserService userService) {
		this.userService = userService;
		samlService.setUserService(userService);
		oidcService.setUserService(userService);
	}

	public UserDomainService getUserDomainService() {
		return userDomainService;
	}

	public void setUserDomainService(UserDomainService userDomainService) {
		this.userDomainService = userDomainService;
		samlService.setUserDomainService(userDomainService);
		oidcService.setUserDomainService(userDomainService);
	}

	public DispatcherService getDispatcherService() {
		return dispatcherService;
	}

	public void setDispatcherService(DispatcherService dispatcherService) {
		this.dispatcherService = dispatcherService;
		samlService.setDispatcherService(dispatcherService);
		oidcService.setDispatcherService(dispatcherService);
	}

	public AccountService getAccountService() {
		return accountService;
	}

	public void setAccountService(AccountService accountService) {
		this.accountService = accountService;
		samlService.setAccountService(accountService);
		oidcService.setAccountService(accountService);
	}

	public PasswordService getPasswordService() {
		return passwordService;
	}

	public void setPasswordService(PasswordService passwordService) {
		this.passwordService = passwordService;
		samlService.setPasswordService(passwordService);
		oidcService.setPasswordService(passwordService);
	}


	public ConfigurationService getConfigurationService() {
		return configurationService;
	}

	public FederationMemberEntityDao getFederationMemberEntityDao() {
		return federationMemberEntityDao;
	}

	public SamlRequestEntityDao getSamlRequestEntityDao() {
		return samlRequestEntityDao;
	}

	public AdditionalDataService getAdditionalData() {
		return additionalData;
	}

	public void setAdditionalData(AdditionalDataService additionalData) {
		this.additionalData = additionalData;
		samlService.setAdditionalData(additionalData);
		oidcService.setAdditionalData(additionalData);
	}

	public void setSessionService(SessionService sessionService) {
		this.sessionService = sessionService;
		samlService.setSessionService(sessionService);
		oidcService.setSessionService(sessionService);
		
	}
	public SamlValidationResults authenticate(String serviceProviderName, String protocol, Map<String, String> response,
			boolean autoProvision) throws Exception {
		
		log.info("authenticate() - serviceProviderName: "+serviceProviderName);
		log.info("authenticate() - protocol: "+protocol);
		log.info("authenticate() - response: "+response);
		log.info("authenticate() - autoProvision: "+autoProvision);
		
		String samlResponse = response.get("SAMLResponse");
		String code = response.get("code");
		if (samlResponse != null)
			return samlService.authenticateSaml(serviceProviderName, protocol, response, autoProvision);
		if (code != null)
			return oidcService.authenticateOidc(serviceProviderName, protocol, response, autoProvision);
		throw new Exception ("Missing SAML or Openid-Connect response");
	}

	protected String toSingleString(SamlValidationResults result, String oid, String friendlyName) {
		return toSingleString(result.getAttributes(), oid, friendlyName);
	}

	protected String toSingleString(Map att, String oid, String friendlyName) {
		String s = toSingleString(att.get(oid));
		if ( s == null)
			s = toSingleString(att.get(friendlyName));
		return s;
	}

	protected String toSingleString(Object object) {
		if (object == null)
			return null;
		else if (object.getClass().isArray())
		{
			String r = null;
			for (Object o: (Object[]) object)
			{
				if (r == null) r = toSingleString(o);
				else r = r + " " + toSingleString(o);
			}
			return r;
		}
		else if (object instanceof Collection)
		{
			String r = null;
			for (Object o: (Collection) object)
			{
				if (r == null) r = toSingleString(o);
				else r = r + " " + toSingleString(o);
			}
			return r;
		} 
		else if (object instanceof Map)
		{
			String r = null;
			for (Object k: ((Map) object).keySet())
			{
				if (r == null) r = toSingleString(k) + ":"+toSingleString(((Map) object).get(k));
				else r = r + " " + toSingleString(k) + ":"+toSingleString(((Map) object).get(k));
			}
			return r;
		}
		else
			return object.toString();
	}

	public SamlRequest generateRequest(String serviceProvider, String identityProvider, String userName, long sessionSeconds) throws InternalErrorException {
		IdentityProviderEntity fm = findIdentityProvider (identityProvider);

		if (fm == null)
			throw new InternalErrorException ("Cannot find identity provider with public id "+identityProvider);
		
		if (fm.getIdpType() == IdentityProviderType.SAML || fm.getIdpType() == IdentityProviderType.SOFFID)
			return samlService.generateSamlRequest(serviceProvider, identityProvider, userName, sessionSeconds);
		else 
			return oidcService.generateOidcRequest(serviceProvider, identityProvider, userName, sessionSeconds);
		
	}
	
	public IdentityProviderEntity findIdentityProvider(String identityProvider) {
		for (FederationMemberEntity fm : federationMemberEntityDao.findFMByPublicId(identityProvider))
			if (fm instanceof IdentityProviderEntity)
				return (IdentityProviderEntity) fm;
		return null;
	}

	public ServiceProviderEntity findServiceProvider(String identityProvider) {
		for (FederationMemberEntity fm : federationMemberEntityDao.findFMByPublicId(identityProvider))
			if (fm instanceof ServiceProviderEntity)
				return (ServiceProviderEntity) fm;
		return null;
	}

	public SamlRequest generateLogout(String serviceProvider, String identityProvider, String userName, boolean forced, boolean backChannel) throws InternalErrorException {
		IdentityProviderEntity fm = findIdentityProvider (identityProvider);

		if (fm == null)
			throw new InternalErrorException ("Cannot find identity provider with public id "+identityProvider);
		
		if (fm.getIdpType() == IdentityProviderType.SAML || fm.getIdpType() == IdentityProviderType.SOFFID)
			return samlService.generateSamlLogout(serviceProvider, identityProvider, userName, forced, backChannel);
		else 
			throw new InternalErrorException ("Single logout not supported for OpeID-Connect protocol");
	}


	public String generateRandomId() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        Hex encoder = new Hex();
        final byte[] buf = new byte[24];
        random.nextBytes(buf);
        return "_" + StringUtils.newStringUsAscii(encoder.encode(buf));
	}

	public SamlValidationResults validateSessionCookie(String sessionCookie) throws InternalErrorException {
		log.info("handleValidateSessionCookie()");
		User u = null;
		try {
			u = checkSamlCookie(sessionCookie);
		} catch (Exception e) {
			// Ignore validation exceptions
		}
		log.info("handleValidateSessionCookie() - u: "+u);
		if ( u == null )
		{
			try {
				u = checkIdpCookie(sessionCookie);
			} catch (Exception e) {
				// Ignore validation exceptions
			}
		}
		SamlValidationResults r = new SamlValidationResults();
		if (u != null)
		{
			r.setValid(true);
			r.setAttributes(new HashMap<String, Object>());
			r.setSessionCookie(sessionCookie);
			r.setIdentityProvider(null);
			r.setUser(u);
		}
		else
			r.setValid(false);
		
		log.info("handleValidateSessionCookie() - r: "+r);
		return r;
	}

	private User checkSamlCookie(String cookie)
			throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, UnknownUserException {

		String value = URLDecoder.decode(cookie,"UTF-8");
		String[] split = value.split(":");
		if (split.length != 2)
			return null;

		SamlRequestEntity entity = samlRequestEntityDao.findByExternalId(split[0]);
		log.info("checkSamlCookie() - entity: "+entity);
		if (entity!=null && entity.getExpirationDate()!=null && !entity.getExpirationDate().before(new Date()) && entity.getKey().equals(split[1]))
		{
			User u = userService.findUserByUserName(entity.getUser());
			if (u != null && u.getActive().booleanValue()) {
				return u;
			} else {
				return null;
			}
		} else {
			log.info("checkSamlCookie() - entity null or expirationDate false or key!=split[1]");
			return null;
		}
	}

	private User checkIdpCookie(String value) throws InternalErrorException, IOException, NoSuchAlgorithmException,
			UnsupportedEncodingException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException,
			CertificateException, NoSuchProviderException, SignatureException {
		int separator = value.indexOf('_');
		if (separator > 0)
		{
			String hash = value.substring(separator+1);
			Long id = Long.decode(value.substring(0, separator));
			for (Session sessio: sessionService.getActiveSessions(id))
			{
				byte digest[] = MessageDigest.getInstance("SHA-256").digest(sessio.getKey().getBytes("UTF-8"));
				String digestString = Base64.encodeBytes(digest);
				if (digestString.equals(hash))
				{
					User u = userService.findUserByUserName(sessio.getUserName());
					if (u != null && u.getActive().booleanValue())
					{
						return u;
					}
				}
				
			}
		}
		return null;
	}
    

	protected PasswordDomain createExternalPasswordDomain () throws InternalErrorException
	{
		PasswordDomain pd = userDomainService.findPasswordDomainByName(EXTERNAL_SAML_PASSWORD_DOMAIN);
		if ( pd == null )
		{
			pd = new PasswordDomain();
			pd.setCode(EXTERNAL_SAML_PASSWORD_DOMAIN);
			pd.setDescription("External SAML systems");
			pd = userDomainService.create(pd);
		}
		for ( UserType ut: userDomainService.findAllUserType())
		{
			PasswordPolicy pp = userDomainService.findPolicyByTypeAndPasswordDomain(ut.getCode(), EXTERNAL_SAML_PASSWORD_DOMAIN);
			if (pp == null)
			{
				pp = new PasswordPolicy();
				pp.setAllowPasswordChange(false);
				pp.setAllowPasswordQuery(false);
				pp.setDescription("External SAML accounts");
				pp.setUserType(ut.getCode());
				pp.setMaximumHistorical(0L);
				pp.setMinimumLength(1L);
				pp.setMaximumPeriod(3650L);
				pp.setMaximumPeriodExpired(3650L);
				pp.setType("A");
				pp.setPasswordDomainCode(EXTERNAL_SAML_PASSWORD_DOMAIN);
				userDomainService.create(pp);
			}
		}
		return pd;
	}

	protected com.soffid.iam.api.System createSamlDispatcher (String publicId) throws InternalErrorException
	{
		com.soffid.iam.api.System s = findDispatcher(publicId);
		if ( s == null )
		{
			createExternalPasswordDomain();
			s = new com.soffid.iam.api.System();
			s.setName(publicId);
			if (s.getName().length() > 25)
				s.setName("#" + System.currentTimeMillis() );
			s.setDescription("External IDP "+publicId);
			s.setAuthoritative(false);
			s.setAccessControl(false);
			s.setReadOnly(true);
			s.setClassName(ES_CAIB_SEYCON_IDP_AGENT_IDP_AGENT);
			s.setManualAccountCreation(true);
			s.setParam0(publicId);
			s.setUsersDomain("DEFAULT");
			PasswordDomain pd = createExternalPasswordDomain();
			s.setPasswordsDomain(pd.getCode());
			s.setPasswordsDomainId(pd.getId());
			s = dispatcherService.create(s);
		}
		return s;
	}

	protected com.soffid.iam.api.System findDispatcher(String publicId) throws InternalErrorException {
		com.soffid.iam.utils.Security.nestedLogin(com.soffid.iam.utils.Security.ALL_PERMISSIONS);
		try {
			for (com.soffid.iam.api.System d: dispatcherService.findDispatchersByFilter(null, ES_CAIB_SEYCON_IDP_AGENT_IDP_AGENT, null, null, null, null))
			{
				if (publicId.equals(d.getParam0()))
					return d;
			}
		} finally {
			com.soffid.iam.utils.Security.nestedLogoff();
		}
		return null;
	}

	public SamlValidationResults authenticate(String serviceProvider, String identityProvider, 
			String user, String password, long sessionSeconds ) throws InternalErrorException, RemoteException, NoSuchAlgorithmException {
		Account acc = accountService.findAccount(user, identityProvider);
		if (acc == null)
		{
			SamlValidationResults r = new SamlValidationResults();
			r.setValid(false);
			r.setFailureReason("Unknown account");
			r.setIdentityProvider(identityProvider);
			r.setPrincipalName(user);
			return r;
		}
		boolean v = passwordService.checkPassword(user, identityProvider, new Password(password), true, true);
		SamlValidationResults r = new SamlValidationResults();
		if (v)
		{
			// Check if the password is expired (in o out of the grace period)
			boolean e = passwordService.checkPassword(user, identityProvider, new Password(password), false, false);
			r.setValid(true);
			if (e) {
				r.setExpired(false);
			} else {
				r.setExpired(true);
				Account ac = accountService.findAccount(user, identityProvider);
				com.soffid.iam.api.System agent = dispatcherService.findDispatcherByName(ac.getSystem());
				String pdName = agent.getPasswordsDomain();
				LinkedList<PasswordPolicy> app = (LinkedList<PasswordPolicy>) userDomainService.findAllPasswordPolicyDomain(pdName);

				Calendar passExp = ac.getPasswordExpiration();
				if (passExp==null) {
					passExp = Calendar.getInstance();
					if (ac.getType() == AccountType.USER) {
						for (String identity: ac.getOwnerUsers()) {
							for (Account ac2: accountService.findUserAccountsByDomain(identity, agent.getPasswordsDomain())) { 
								if (ac2.getPasswordExpiration() != null) {
									passExp = ac2.getPasswordExpiration();
									break;
								}
							}
							
						}
					}
				}
				Calendar today = Calendar.getInstance();
				long MILISEGUNDOS_POR_DIA = 24*60*60*1000;
				long daysExpired = (today.getTimeInMillis()-passExp.getTimeInMillis())/MILISEGUNDOS_POR_DIA;
				for (PasswordPolicy pp : app) {
					if (pp.getUserType().equals(ac.getPasswordPolicy())) {
						Long daysGrace = pp.getMaximumPeriodExpired();
						if (daysGrace!=null && daysExpired>daysGrace.intValue()) {
							r.setValid(false);
							break;
						}
					}
				}
			}

			StringBuffer sb = new StringBuffer();
			SecureRandom sr = new SecureRandom();
			for (int i = 0; i < 180; i++)
			{
				int random = sr.nextInt(64);
				if (random < 26)
					sb.append((char) ('A'+random));
				else if (random < 52)
					sb.append((char) ('a'+random-26));
				else if (random < 62)
					sb.append((char) ('0'+random-52));
				else if (random < 63)
					sb.append('+');
				else
					sb.append('/');
			}
			
			String newID = generateRandomId();
			SamlRequestEntity reqEntity = samlRequestEntityDao.newSamlRequestEntity();
			reqEntity.setHostName(serviceProvider);
			reqEntity.setDate(new Date());
			reqEntity.setExpirationDate(new Date(System.currentTimeMillis()+sessionSeconds * 1000L));
			reqEntity.setExternalId(newID);
			reqEntity.setFinished(false);
			reqEntity.setKey(sb.toString());
			r.setIdentityProvider(identityProvider);
			
			
			r.setUser(searchUser(identityProvider, user));
			if (r.getUser() != null) {
				reqEntity.setUser(r.getUser().getUserName());
				r.setAttributes( ServiceLocator.instance().getUserService().findUserAttributes(r.getUser().getUserName()) );
			}
			if (r.isValid())
				r.setSessionCookie(reqEntity.getExternalId()+":"+reqEntity.getKey());
			reqEntity.setFinished(true);
			samlRequestEntityDao.create(reqEntity);

			return r;
		}
		else
		{
			r.setFailureReason("Wrong user name ar password");
		}
		return r;
	}

	private User searchUser(String identityProvider, String user) throws InternalErrorException {
		Account account = accountService.findAccount( user , identityProvider);
		if (account != null)
		{
			if (account.getType().equals(AccountType.USER) && account.getOwnerUsers().size() == 1)
			{
				return getUserService().findUserByUserName(account.getOwnerUsers().iterator().next());
			}
		}
		return null;
	}

	public User findAccountOwner(String principalName, String identityProvider, Map<String, ? extends Object> map,
			boolean autoProvision) throws Exception
	{
		log.info("searchUser()");
		
		com.soffid.iam.api.System dispatcher = createSamlDispatcher(identityProvider);
		Account account = accountService.findAccount( principalName , dispatcher.getName());
		log.info("searchUser() - account: "+account);
		if (account != null)
		{
			if (account.getType().equals(AccountType.USER) && account.getOwnerUsers().size() == 1)
			{
				log.info("searchUser() - return: account.getOwnerUsers().iterator().next()");
				updateAccountAttributes ( account, map);
				return getUserService().findUserByUserName(account.getOwnerUsers().iterator().next());
			}
			if ( ! account.getType().equals(AccountType.IGNORED))
				throw new InternalErrorException( String.format("Account %s at system %s is reserved", 
						principalName,
						dispatcher.getName()));
		}
		// Update account attributes
		
		log.info("searchUser() - provision: "+autoProvision);
		String provisionScript = null;
		for (FederationMemberEntity fm: federationMemberEntityDao.findFMByPublicId(identityProvider))
		{
			if (fm instanceof IdentityProviderEntity)
			{
				if (fm.getScriptParse() != null && ! fm.getScriptParse().trim().isEmpty())
					provisionScript = fm.getScriptParse();
			}
		}

		if (autoProvision || provisionScript != null )
		{
			User u = new User();
			u.setActive(true);
			u.setUserName(identityProvider + "#" +principalName);
			u.setFirstName( toSingleString( map, "urn:oid:2.5.4.42", "givenName") );
			u.setLastName ( toSingleString( map, "urn:oid:2.5.4.4", "sn")) ;
			u.setUserType("E");
			u.setPrimaryGroup("world");
			u.setComments(String.format("Autoprovisioned from %s identity provider", identityProvider));
			u.setCreatedByUser(u.getUserName());
			u.setCreatedDate(Calendar.getInstance());
			u.setHomeServer("null");
			u.setProfileServer("null");
			u.setMailServer("null");
			Map<String,Object> attributes = (Map<String, Object>) map;

			if (provisionScript != null) {
				try {
					Interpreter interpreter = new Interpreter();
					interpreter.set("user", u); //$NON-NLS-1$
					interpreter.set("attributes", attributes); //$NON-NLS-1$
					interpreter.set("serviceLocator", ServiceLocator.instance()); //$NON-NLS-1$
					log.info("searchUser() - execute scriptParse");
					Object r = interpreter.eval( provisionScript );
					if ( r == null || r.equals(Boolean.FALSE))
					{
						return null;
					}
					else if ( ! (r instanceof String))
					{
						throw new InternalErrorException("Autoprovision script for "+identityProvider+" returned an object of class "+r.getClass().toString()+" when it should return a String object");
					}
					else
					{
						u.setUserName((String) r);
					}
				} catch (EvalError e) {
					throw new InternalErrorException(String.format("Error evaluating provisioning script for identity provider %s", identityProvider),
							e);
				}
			}
			
			log.info("searchUser() - trying to create the user...");
			User u2 = userService.findUserByUserName(u.getUserName());
			if (u2 != null) u = u2;
			else {
				WorkflowInitiator wi = new WorkflowInitiator();
				wi.federationMemberEntityDao = getFederationMemberEntityDao();
				wi.bpmEngine = getBpmEngine();
				if (wi.startWF(identityProvider, u, map)) {
					u = userService.findUserByUserName(u.getUserName());
					if (u == null)
						return null;
				}
				else
					u = userService.create(u);
			}
			log.info("searchUser() - user created!");
			log.info("searchUser() - u.getShortName(): "+u.getShortName());
			for (String att: attributes.keySet())
			{
				Collection<DataType> md = additionalData.findDataTypesByScopeAndName(MetadataScope.USER, att);
				Object v = attributes.get(att);
				if (md != null && ! md.isEmpty() && v != null && md.iterator().next().getCode().equals(att))
				{
					UserData data = new UserData();
					data.setAttribute(att);
					if ( v instanceof Calendar )
					{
						data.setDateValue( (Calendar) v );
					}
					else if ( v instanceof Date )
					{
						Calendar c = Calendar.getInstance();
						c.setTime( (Date) v );
						data.setDateValue(c);
					}
					else
					{
						data.setValue(v.toString());
					}
					data.setUser(u.getUserName());
					additionalData.create(data);
					log.info("searchUser() - additionalData created: "+data.getAttribute());
				}
			}
			// Register account
			try {
				account = accountService.createAccount(u, dispatcher, principalName);
				updateAccountAttributes ( account, map);
				log.info("searchUser() - account created");
			} catch (NeedsAccountNameException e) {
				throw new InternalErrorException( String.format("Account %s at system %s is reserved", 
						principalName,
						dispatcher.getName()));
			} catch (AccountAlreadyExistsException e) {
				throw new InternalErrorException( String.format("Account %s at system %s is reserved", 
						principalName,
						dispatcher.getName()));
			}
			return u;
		}
		else
			return null;
	}

	private void updateAccountAttributes(Account account, Map<String, ? extends Object> attributes) throws InternalErrorException {
		long nextOrder = 1L ;
		for (String att: attributes.keySet())
		{
			if (att.length() < 25)
			{
				DataType md = additionalData.findSystemDataType(account.getSystem(), att);
				Object v = attributes.get(att);
				if (v != null)
				{
					if (md == null)
					{
						md = new DataType();
						md.setSystemName(account.getSystem());
						md.setCode(att);
						md.setLabel(att);
						md.setType(TypeEnumeration.STRING_TYPE);
						md.setOrder( nextOrder );
						for ( DataType md2: additionalData.findSystemDataTypes(account.getSystem()))
						{
							log.info("Checking data type "+md2.getCode()+" order "+md2.getOrder());
							if (md2.getOrder().longValue() >= md.getOrder().longValue())
								md.setOrder(new Long (md2.getOrder().longValue()+1));
						}
						log.info("Creating data type "+md.getCode()+" order "+md.getOrder());
						additionalData.create(md);
						nextOrder = md.getOrder().longValue() + 1L;
					}
	
					UserData data = new UserData();
					data.setAccountName(account.getName());
					data.setSystemName(account.getSystem());
					data.setAttribute(att);
					if ( v instanceof Calendar )
					{
						data.setValue( DateFormat.getDateTimeInstance().format((Calendar) v ));
					}
					else if ( v instanceof Date )
					{
						data.setValue( DateFormat.getDateTimeInstance().format((Date) v ));
					}
					else if (v.toString().length() < 256)
					{
						data.setValue(v.toString());
					}
					accountService.updateAccountAttribute(data);
				}
			}
		}
	}

	public void expireSessionCookie(String cookie) throws InternalErrorException, UnsupportedEncodingException, NoSuchAlgorithmException {
		String value = URLDecoder.decode(cookie,"UTF-8");
		
		// First. Remove Federation core cookie
		String[] split = value.split(":");
		if (split.length == 2)
		{
			SamlRequestEntity entity = samlRequestEntityDao.findByExternalId(split[0]);
			if (entity != null) {
				entity.setExpirationDate(new Date());
				samlRequestEntityDao.update(entity);
				User u = userService.findUserByUserName(entity.getUser());
				for (Session sessio: sessionService.getActiveSessions(u.getId()))
				{
					if (sessio.getUrl() != null)
					{
						sessionService.destroySession(sessio);
					}
					
				}
			}
		}
		// Second. Remove IDP session generated  cookie
		int separator = value.indexOf('_');
		if (separator > 0)
		{
			String hash = value.substring(separator+1);
			Long id = Long.decode(value.substring(0, separator));
			for (Session sessio: sessionService.getActiveSessions(id))
			{
				byte digest[] = MessageDigest.getInstance("SHA-256").digest(sessio.getKey().getBytes("UTF-8"));
				String digestString = Base64.encodeBytes(digest);
				if (digestString.equals(hash))
				{
					sessionService.destroySession(sessio);
				}
				
			}
		}
	}

	public BpmEngine getBpmEngine() {
		return bpmEngine;
	}

	public void setBpmEngine(BpmEngine bpmEngine) {
		this.bpmEngine = bpmEngine;
	}

}

