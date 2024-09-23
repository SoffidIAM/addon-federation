package com.soffid.iam.addons.federation.service;

import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.rmi.RemoteException;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.UserIdentity;

import com.soffid.iam.addons.federation.esso.OtpSelector;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.AccessTree;
import com.soffid.iam.api.AccessTreeExecution;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.AttributeVisibilityEnum;
import com.soffid.iam.api.Audit;
import com.soffid.iam.api.AuthorizationRole;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.Network;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.PasswordPolicy;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.System;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.api.VaultFolder;
import com.soffid.iam.common.security.SoffidPrincipal;
import com.soffid.iam.security.SoffidPrincipalImpl;
import com.soffid.iam.service.AccountService;
import com.soffid.iam.service.AdditionalDataService;
import com.soffid.iam.service.AuditService;
import com.soffid.iam.service.AuthorizationService;
import com.soffid.iam.service.DispatcherService;
import com.soffid.iam.service.NetworkService;
import com.soffid.iam.service.NetworkServiceImpl;
import com.soffid.iam.service.UserDomainService;
import com.soffid.iam.sync.engine.session.SessionManager;
import com.soffid.iam.sync.service.SecretStoreService;
import com.soffid.iam.sync.web.Messages;
import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.comu.AccountAccessLevelEnum;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.exception.AccountAlreadyExistsException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class EssoServiceImpl extends EssoServiceBase {
	Log log = LogFactory.getLog(getClass());
	Map<String, TemporarySoffidPrincipal> principals = new HashMap<>();

	public SoffidPrincipal getPrincipal(String name) throws InternalErrorException {
		TemporarySoffidPrincipal p = principals.get(name);
		if (p != null) { 
			p.refresh();
			return p;
		}
		Account acc = getAccountService().findAccount(name, getDispatcherService().findSoffidDispatcher().getName());
		if (acc == null || acc.isDisabled() || acc.getType() != AccountType.USER)
			throw new SecurityException("User unknown or inactive");
		User u = getUserService().findUserByUserName(acc.getOwnerUsers().iterator().next());
		TemporarySoffidPrincipal spi = new TemporarySoffidPrincipal(
				Security.getCurrentTenantName()+"\\"+acc.getName(), 
				u.getId());
		spi.refresh();
		principals.put(name, spi);
		return spi;
	}

	public String getUserAccount(String user) throws InternalErrorException {
		for (UserAccount acc: getAccountService().findUsersAccounts(user, getDispatcherService().findSoffidDispatcher().getName()) ) {
			if (! acc.isDisabled() && acc.getType() == AccountType.USER)
				return acc.getName();
		}
		throw new InternalErrorException("No account available for "+user);
	}
	
	@Override
	protected boolean handleAuditPasswordQuery(String user, String key, String account, String system, String url,
			String app, String sourceIp) throws Exception {
		User usuari = getUserService().findUserByUserName(user);
		if (usuari == null)
			return false;

		for (Session sessio : getSessionService().getActiveSessions(usuari.getId())) {
			if (sessio.getKey().equals(key)) {
				Audit audit = new Audit();
				audit.setAction(url == null ? "E" : "W");
				audit.setAccount(account);
				audit.setApplication(app == null ? url : app);
				audit.setAuthor(sessio.getUserName());
				audit.setDatabase(system);
				audit.setCalendar(Calendar.getInstance());
				audit.setObject("SSO");
				audit.setSourceIp(sourceIp);
				getAuditService().create(audit);
				return true;
			}
		}
		return false;
	}

	protected String handleDoChangeSecret(String sessionKey, String user, 
			String secret, String account, String system, String ssoAttribute, String description,
			String value) throws Exception {
		User usuari = getUserService().findUserByUserName(user);
		String userAccount = getUserAccount(user);
        Security.nestedLogin(userAccount, new String[] {
        		Security.AUTO_USER_QUERY+Security.AUTO_ALL,
        		Security.AUTO_ACCOUNT_QUERY+Security.AUTO_ALL,
        		Security.AUTO_ACCOUNT_UPDATE+Security.AUTO_ALL,
        		Security.AUTO_ACCOUNT_CREATE+Security.AUTO_ALL
        });
        try {

			Collection<Session> activeSessions = getSessionService().getActiveSessions(usuari.getId());
			for (Session sessio : activeSessions) {
				if (sessio.getKey().equals(sessionKey)) {
					final String result = doChangeSecret(usuari, userAccount, secret, account, 
							system, ssoAttribute,
							description, value);
					return result;
				}
			}
        } finally {
        	Security.nestedLogoff();
        }
		return "ERROR";
	}

	private String doChangeSecret(User usuari, String userAccount, String secret, String account, String system,
			String ssoAttribute, String description, String value) throws InternalErrorException, RemoteException,
			AccountAlreadyExistsException, UnsupportedEncodingException {

		SoffidPrincipal p = getPrincipal(userAccount);
		Security.nestedLogin(p);
		try {
			SecretStoreService sss = getSecretStoreService();
			if (secret != null) {
				sss.putSecret(usuari, secret, new Password(value));
			} else if (account == null || account.trim().length() == 0) {
				if (canCreateAccount(usuari, system)) {
					Account acc = createAccount(system, usuari, description);
					return "OK|" + acc.getName();
				} else {
					log.warn("User "+usuari.getUserName()+" is not authorized to create account "+ account);
					return "ERROR|Not authorized";
				}
			} else if (system != null && account != null && system.length() > 0 && account.length() > 0) {
				Account acc = getAccountService().findAccount(account, system);

				if (acc == null) {
					log.warn("User "+usuari.getUserName()+" is trying to modify non existing account "+
							account + "@" + system);
					return Messages.getString("ERROR|Not authorized"); //$NON-NLS-1$
				}

				if (acc instanceof UserAccount) {
					if (!((UserAccount) acc).getUser().equals(usuari.getUserName())) {
						log.warn("User "+usuari.getUserName()+" is trying to modify personal account "+
								account + "@" + system);
						return Messages.getString("ERROR|Not authorized"); //$NON-NLS-1$
					}
				} else {
					boolean found = false;
					for (String user : getAccountService().getAccountUsers(acc,
							AccountAccessLevelEnum.ACCESS_USER)) {
						if (user.equals(usuari.getUserName())) {
							found = true;
							break;
						}
					}
					if (!found) {
						log.warn("User "+usuari.getUserName()+" is trying to modify account "+
							account+"@"+system+" without permission");
						return Messages.getString("ERROR|Not authorized"); //$NON-NLS-1$
					}
				}

				AccountService acs = getAccountService();

				if (ssoAttribute == null || ssoAttribute.length() == 0) {
					sss.setPassword(acc.getId(), new Password(value));

					UserDomainService dominiService = getUserDomainService();
					DispatcherService dispatcherService = getDispatcherService();
					System dispatcher = dispatcherService.findDispatcherByName(system);
					PasswordPolicy politica = dominiService.findPolicyByTypeAndPasswordDomain(acc.getPasswordPolicy(),
							dispatcher.getPasswordsDomain());
					Long l = null;

					if (politica != null && politica.getMaximumPeriod() != null && politica.getType().equals("M")) //$NON-NLS-1$
						l = politica.getMaximumPeriod();
					else if (politica != null && politica.getRenewalTime() != null && politica.getType().equals("A")) //$NON-NLS-1$
						l = politica.getRenewalTime();
					acs.updateAccountPasswordDate(acc, l);
					getLogonService().propagatePassword(account, system, value);
				} else {
					if (value.length() < 1024) {

						if (ssoAttribute.equals("Server")) {
							if (value.length() > 256)
								value = value.substring(0, 255);
							acc.setServerName(value);
						} else if (ssoAttribute.equals("URL")) {
							if (value.length() > 256)
								value = value.substring(0, 255);
							acc.setLoginUrl(value);
						} else {
							String actualAttribute = "SSO:" + ssoAttribute;
							acc.getAttributes().put(actualAttribute, value);
							if (acc.getLoginName() == null || acc.getLoginName().equals(acc.getName())) {
								int i = value.indexOf("=");
								if (i > 0) {
									String vv = URLDecoder.decode(value.substring(i + 1), "UTF-8");
									if (!vv.isEmpty())
										acc.setLoginName(vv);
								}
							}
							// Attribute not found
							AdditionalDataService metadataService = getAdditionalDataService();
							DataType md = metadataService.findSystemDataType(system, actualAttribute);
							if (md == null) {
								md = new DataType();
								md.setAdminVisibility(AttributeVisibilityEnum.EDITABLE);
								md.setUserVisibility(AttributeVisibilityEnum.EDITABLE);
								md.setOperatorVisibility(AttributeVisibilityEnum.EDITABLE);
								md.setCode(actualAttribute);
								md.setVisibilityExpression("false");
								if (ssoAttribute.equals("Server")) {
									md.setLabel("Server");
									md.setType(TypeEnumeration.STRING_TYPE);
								} else {
									md.setLabel("Form data");
									md.setType(TypeEnumeration.SSO_FORM_TYPE);
								}
								md.setSize(1024);
								md.setOrder(0L);
								md.setSystemName(system);
								md.setRequired(false);
								md = metadataService.create(md);
							}
						}
						acs.updateAccount2(acc);
					}
				}

			} else {
				return Messages.getString("ChangeSecretServlet.NotAuth"); //$NON-NLS-1$
			}
		} finally {
			Security.nestedLogoff();
		}
		return "OK"; //$NON-NLS-1$
	}

	/**
	 * 
	 * @param system
	 * @return
	 * @throws InternalErrorException
	 */
	private long findLastAccount(String system) throws InternalErrorException {
		long bits = 0;
		long top = 0;
		long attempt = 1;
		/**
		 * Find radix the first account with number = 2 ^ radix
		 */
		do {
			Account acc = getAccountService().findAccount("" + attempt, system);
			if (acc == null)
				break;
			top = attempt;
			attempt = attempt + attempt;
			bits++;
		} while (true);
		/**
		 * Now look for the other bits top exists attempt does not exist
		 */
		long step = top;
		while (bits > 1) {
			step = step / 2;
			attempt = top + step;
			Account acc = getAccountService().findAccount("" + attempt, system);
			if (acc != null)
				top = attempt;
			bits--;
		}
		return top;
	}

	private Account createAccount(String system, User owner, String description)
			throws InternalErrorException, AccountAlreadyExistsException {
		long i = findLastAccount(system) + 1;

		Account acc = new Account();
		acc.setName("" + i);
		acc.setDescription(description);
		acc.setSystem(system);
		acc.setOwnerUsers(new LinkedList<String>());
		acc.getOwnerUsers().add(owner.getUserName());
		String ssoPolicy = ConfigurationCache.getProperty("AutoSSOPolicy"); //$NON-NLS-1$
		if (ssoPolicy == null)
			throw new InternalErrorException(Messages.getString("ChangeSecretServlet.22")); //$NON-NLS-1$
		acc.setType(AccountType.IGNORED);
		acc.setPasswordPolicy(ssoPolicy);
// Search for personal folder
		VaultFolder vf = getVaultService().getPersonalFolder();

		if (vf != null) {
			acc.setVaultFolder(vf.getName());
			acc.setVaultFolderId(vf.getId());
		}
		return getAccountService().createAccount(acc);
	}

	private boolean canCreateAccount(User usuari, String system) throws InternalErrorException {
		String authSystem = ConfigurationCache.getProperty("AutoSSOSystem"); //$NON-NLS-1$
		if (authSystem == null || authSystem.equals(system)) {
			System soffid = getDispatcherService().findSoffidDispatcher();
			for (UserAccount account : getAccountService().findUsersAccounts(usuari.getUserName(), soffid.getName())) {
				Collection<AuthorizationRole> auts = getAuthorizationService()
						.getUserAuthorization("sso:manageAccounts", account.getName());
				if (!auts.isEmpty())
					return true;
			}
			return false;
		} else {
			if (authSystem == null) {
				log.info("Missing configuration property AutoSSOSystem. Please,  configure to enable ESSO clients");
			}
			return false;
		}
	}

	@Override
	protected Session handleCreateDummySession(String user, String host, String clientIP, String port) throws Exception {
    	NetworkService xs = getNetworkService();
    	Host maq = xs.findHostByIp(com.soffid.iam.utils.Security.getClientIp());
    	if (maq == null)
    	{
    		throw new InternalErrorException("Unknown host "+com.soffid.iam.utils.Security.getClientIp());
    	}
    	Host client = null;
    	if (clientIP != null)
    		
    	{
    		client = xs.findHostByIp(clientIP);
        	if (client == null)
        	{
        		client = new Host();
        		client.setName(clientIP);
        		client.setIp(clientIP);
        	}
    	}
        return SessionManager.getSessionManager().addSession(
                maq,
                Integer.parseInt(port),
                user,
                null, // Password,
                client,
                null,  // Sense clau
                false, false, null); // Sense tancar altres sessions
	}

	@Override
	protected String[] handleGetHostAdministration(String hostname, String hostIP, String user) throws Exception {
        NetworkService xs = getNetworkService();
        AuthorizationService as = getAuthorizationService();
        SoffidPrincipal principal = getPrincipal(getUserAccount(user));
        
        boolean trackIp = "true".equals( ConfigurationCache.getProperty("SSOTrackHostAddress"));
        Host maq = xs.findHostByName(hostname);
        if (maq == null)
            throw new InternalErrorException(String.format(
				Messages.getString("GetHostAdministrationServlet.NoHostFoundMessage"), hostname)); //$NON-NLS-1$
        else if (maq.getIp() == null)
        {
            InternalErrorException ex = new InternalErrorException("IncorrectHostException"); //$NON-NLS-1$
            log.warn(String.format("Attempt to obtain admin user-password for host '%1$s' from mismatch IP '%2$s'", 
				hostname, hostIP), ex);
            throw ex;
        }
        else if (trackIp && !maq.getIp().equals(hostIP))
        {
            InternalErrorException ex = new InternalErrorException("IncorrectHostException"); //$NON-NLS-1$
            log.warn(String.format("Attempt to obtain admin user-password for host '%1$s' from mismatch IP '%2$s'", 
				hostname, hostIP), ex);
            throw ex;
        }

        Security.nestedLogin(principal);
        try
        {
            boolean authorized = false;
            for (String auth: principal.getRoles())
            {
                if (auth.equals(Security.AUTO_HOST_ALL_SUPPORT_VNC))
                {
                    authorized = true;
                    break;
                }
            }
            if (!authorized)
            {
                Long nivell = xs.findAccessLevelByHostNameAndNetworkName(maq.getName(), maq.getNetworkCode());
                if (nivell.longValue() >= NetworkServiceImpl.SUPORT)
                    authorized = true;
            }
            
            if ( authorized )
            {
                String userPass[] = xs.getHostAdminUserAndPassword(hostname);
                if (userPass[0] == null || userPass[1] == null)
                    throw new InternalErrorException(Messages.getString("GetHostAdministrationServlet.NoAdminAccountMessage")); //$NON-NLS-1$
                return userPass; //$NON-NLS-1$
            }
            else
            {
                Audit auditoria = new Audit();
                auditoria.setAction("N"); // Administrador //$NON-NLS-1$
                auditoria.setHost(hostname);
                auditoria.setAuthor(user);
                auditoria.setObject("SC_ADMMAQ"); //$NON-NLS-1$
                auditoria.setCalendar(Calendar.getInstance());
    
                AuditService auditoriaService = getAuditService();
                auditoriaService.create(auditoria);
                throw new InternalErrorException(Messages.getString("GetHostAdministrationServlet.UnauthorizedUser")); //$NON-NLS-1$
            }
        }
        finally
        {
            Security.nestedLogoff();
        }
	}

	@Override
	protected AccessTree handleFindApplicationAccessById(String user, Long id) throws Exception {

		if (user != null) {
	        SoffidPrincipal principal = getPrincipal(getUserAccount(user));
	        Security.nestedLogin(principal);
		}
        try {
			AccessTree app = getEntryPointService().findApplicationAccessById(id.longValue());
			if (app != null && ! getEntryPointService().canExecute(app))
				return null;
			else
				return app;
        } finally {
        	if (user != null) Security.nestedLogoff();
        }
	}

	@Override
	protected Collection<AccessTree> handleFindApplicationAccessByCode(String user, String code) throws Exception {
		if (user != null) {
	        SoffidPrincipal principal = getPrincipal(getUserAccount(user));
	        
	        Security.nestedLogin(principal);
		}
        try {
			Collection<AccessTree> l = getEntryPointService().findApplicationAccessByFilter("%", code, "%", "%", "%", "%");
			for (Iterator<AccessTree> iterator = l.iterator(); iterator.hasNext();) {
				AccessTree at = iterator.next();
				if (! getEntryPointService().canExecute(at))
					iterator.remove();
			}
			return l;
        } finally {
        	if (user != null) Security.nestedLogoff();
        }
	}

	@Override
    public AccessTreeExecution handleGetExecution (AccessTree entryPoint, String remoteIp) throws InternalErrorException {
		Network network = getNetworkService().findNetworkByIpAddress(remoteIp);
		String scope = network == null ? "I" :
			Boolean.TRUE.equals(network.getLanAccess()) ? "L" :
			network.getMask().equals("0.0.0.0") ? "I" :
				"W";
		for (AccessTreeExecution exe: getEntryPointService().getExecutions(entryPoint)) {
			if (exe.getScope().equals(scope))
				return exe;
		}
		return null;
    }

	@Override
	protected Collection<AccessTree> handleFindChildren(String user, AccessTree parent) throws Exception {
		if (user != null) {
	        SoffidPrincipal principal = getPrincipal(getUserAccount(user));
	        
	        Security.nestedLogin(principal);
		}
        try {
			return getEntryPointService().findChildren(parent);
        } finally {
        	if (user != null) Security.nestedLogoff();
        }
	}

	@Override
	protected AccessTree handleFindRootAccessTree(String user) throws Exception {
		if (user != null) {
	        SoffidPrincipal principal = getPrincipal(getUserAccount(user));
	        
	        Security.nestedLogin(principal);
		}
        try {
			return getEntryPointService().findRoot();
        } finally {
        	if (user != null) Security.nestedLogoff();
        }
	}

	@Override
	protected Host handleFindHostBySerialNumber(String serialNumber) throws Exception {
		return getNetworkService().findHostBySerialNumber(serialNumber);
	}

	@Override
	protected void handleSetHostAdministration(String hostSerial, String user, Password password)
			throws Exception {
		getNetworkService().setAdministratorPassword(hostSerial, user, password.getPassword());
	}

	@Override
	protected Host handleRegisterDynamicIP(String nomMaquina, String ip, String serialNumber) throws Exception {
		return getNetworkService().registerDynamicIP(nomMaquina, ip, serialNumber);
	}

	@Override
	protected String handleQuery(String path, String format, String ipAddress) throws Exception {
		StringWriter w = new StringWriter();
		getQueryService().query(path, format, ipAddress, w);
		return w.toString();
	}

	@Override
	protected Challenge handleUpdateAndRegisterChallenge(Challenge challenge, boolean textPush) throws Exception {
		boolean r = new OtpSelector().updateChallenge(challenge, null, textPush);
		if (r) {
			getLogonService().registerChallenge(challenge);
			return challenge;
		}
		else
			return null;
	}

}


class TemporarySoffidPrincipal extends SoffidPrincipalImpl {
	long timestamp;
	
	public TemporarySoffidPrincipal(String accountName, Long accountId) {
		super (accountName,
				null, null, null, 
				new LinkedList<>(), new LinkedList<>(), new LinkedList<>(), 
				new LinkedList<>(), new LinkedList<>(), new LinkedList<>(),
				accountId);
		fetchPrincipalProperties();
		timestamp = java.lang.System.currentTimeMillis();
	}

	public void refresh() {
		if (timestamp < java.lang.System.currentTimeMillis() - 10 * 60 * 1000L) { // 10 minutes cache
			fetchPrincipalProperties();
			timestamp = java.lang.System.currentTimeMillis();
		}
	}
}