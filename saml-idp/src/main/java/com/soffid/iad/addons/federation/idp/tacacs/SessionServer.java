package com.soffid.iad.addons.federation.idp.tacacs;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.LogRecord;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.idp.radius.server.RadiusException;
import com.soffid.iam.addons.federation.idp.radius.server.RadiusUtil;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.api.User;
import com.soffid.iam.service.OTPValidationService;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.comu.TipusSessio;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.InvalidPasswordException;
import es.caib.seycon.ng.exception.SoffidStackTrace;
import es.caib.seycon.ng.exception.UnknownUserException;

/**
 * @author Chris.Janicki@augur.com
 * Copyright 2016 Augur Systems, Inc.  All rights reserved.
 */
public class SessionServer extends Session
{
	Log log = LogFactory.getLog(getClass());
	
	private static final boolean DEBUG = false;
	Password oldPassword;
	Password newPassword;
	String user;
	Account account;
	private boolean interactivoLogin;
	private AuthenticationContext authenticationContext;
	private boolean interactiveLogin;
	private MessageDigest md5Digest;

	private boolean changingPassword;

	private int step = 0;

	private Password newPassword2;

	private Password password;

	private Password otp;

	private byte privilegeLevel;
	
	/** Server-side constructor */
	SessionServer(TAC_PLUS.AUTHEN.SVC svc, String port, String rem_addr, byte priv_lvl, TacacsReader tacacs, byte[] sessionID)
	{
		super(svc, port, rem_addr, priv_lvl, tacacs, sessionID);
	}
	
	
	/**
	 * TODO: IMPLEMENT SERVER RESPONSES TO CLIENT REQUESTS!!!
	 * @param p
	 * @throws IOException 
	 */
	@Override synchronized void handlePacket(Packet p) throws IOException
	{
		super.handlePacket(p);
		Packet r;
		if (DEBUG) { System.out.println("Received <-- "+p); }
		switch(p.header.type)
		{
			case AUTHEN:
				try {
					if (p instanceof AuthenStart)
						r = handleAuthenticationStart((AuthenStart) p);
					else if (p instanceof AuthenContinue)
						r = handleAuthenticationContinue((AuthenContinue) p);
					else {
						r = new AuthenReply
								(
									p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
									TAC_PLUS.AUTHEN.STATUS.FAIL, 
									FLAG_ZERO,
									"Wrong authentication package.",
									"Wrong authentiaction package."
								);
	
					}
				} catch (Exception e) {
					log.warn("Error processing tacacs request "+p, e);
					r = errorMessage(p);
				}
				tacacs.write(r);
				break;
			case AUTHOR:
				try {
					List<Argument> arguments = new LinkedList<>();
					AuthorRequest ar = (AuthorRequest) p;
					if (! new AuthorizationChecker().hasSecurityLevel(ar.priv_lvl, tacacs.getServiceProvider().getSystem(), ar.user))
					{
						r = new AuthorReply
						(
							p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.AUTHOR.STATUS.FOLLOW, 
							"",
							"Not authorized to security level "+ar.priv_lvl,
							null
						);
						
					}
					else if (new AuthorizationChecker().validate((AuthorRequest) p, tacacs, arguments))
						r = new AuthorReply
						(
							p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.AUTHOR.STATUS.FOLLOW, 
							"",
							"",
							arguments.toArray(new Argument[arguments.size()])
						);
					else
						r = new AuthorReply
						(
							p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.AUTHOR.STATUS.FOLLOW, 
							"",
							"",
							null
						);
				} catch (Exception e) {
					log.warn("Error processing tacacs request "+p, e);
					r = new AuthorReply (p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.AUTHOR.STATUS.FAIL, 
							"Error processing authorization",
							"Error processing authorization",
							null
							);
				}
				tacacs.write(r);
				break;
			case ACCT:
				try {
					doRegisterAccounting ((AcctRequest) p);
					r = new AcctReply(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.ACCT.STATUS.SUCCESS, 
							"",
							""
							);
				} catch (Exception e) {
					log.warn("Error processing tacacs request "+p, e);
					r = new AcctReply(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.ACCT.STATUS.ERROR, 
							"Error processing accounting",
							"Error processing accounting"
							);
				}
				tacacs.write(r);
				break;
		}
	}


	private void doRegisterAccounting(AcctRequest p) throws InternalErrorException, IOException, UnknownUserException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		final SessionService ss = new RemoteServiceLocator().getSessionService();
		final ServerService serverService = new RemoteServiceLocator().getServerService();
		if ((((int)p.flags) & TAC_PLUS.ACCT.FLAG.START.code()) != 0) {
			account = serverService.getAccountInfo(p.user, 
					tacacs.getServiceProvider().getSystem());
			if (account != null && account.getType() == AccountType.USER) {
				String taskId = "";
				for (Argument param: p.arguments) 
					if (param.getAttribute().equals("task_id"))
						taskId = param.getValue();
				ss.registerSession(account.getOwnerUsers().iterator().next(), 
						IdpConfig.getConfig().getFederationMember().getHostName(), 
						p.rem_addr, 
						0, 
						taskId, "TAC+");
//	        	LogRecorder.getInstance().addSuccessLogEntry("TACACS+", p.user, "P", tacacs.getServiceProvider().getName(), p.rem_addr, 
//	        			null, null, "TACACS_"+taskId);
			}
		}
		else if ((((int)p.flags) & TAC_PLUS.ACCT.FLAG.STOP.code()) != 0)
		{
			account = serverService.getAccountInfo(p.user, 
					tacacs.getServiceProvider().getSystem());
			if (account != null && account.getType() == AccountType.USER) {
				String taskId = "";
				User u = serverService.getUserInfo(account.getName(), account.getSystem());
				for (Argument param: p.arguments) 
					if (param.getAttribute().equals("task_id"))
						taskId = param.getValue();
				for (com.soffid.iam.api.Session session: ss.getActiveSessions(u.getId()))
				{
					if (session.getAuthenticationMethod().equals("TAC+") &&
							session.getKey() != null && session.getKey().equals(taskId) &&
							session.getServerHostName().equals(IdpConfig.getConfig().getFederationMember().getHostName())) {
						ss.destroySession(session);
					}
				}
//	        	LogRecorder.getInstance().flushLogoutEntry("TACACS_"+taskId);
			}
		}
	}


	private Packet handleAuthenticationContinue(AuthenContinue p) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		if (interactiveLogin)
			return doInteractiveLogin(p);
		else
			return doInteractiveChangePassword(p);
	}


	private Packet handleAuthenticationStart(AuthenStart p) throws Exception {
		this.user = p.username;
		switch (p.action) {
		case LOGIN:
			return handleAuthenticationStartLogin(p);
		case CHPASS:
			return handleChangePassword(p);
		default:
			return errorMessage(p);
		}
	}


	private Packet handleChangePassword(AuthenStart p) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		changingPassword = true;
		step = 0;
		return doInteractiveChangePassword(p);
	}


	private Packet handleAuthenticationStartLogin(AuthenStart p) throws Exception {
		privilegeLevel = p.priv_lvl;
		return doLogin(p);
	}


	private Packet doLogin(AuthenStart p) throws Exception {
		switch (p.type) {
		case ASCII: 
			interactiveLogin = true;
			return doInteractiveLogin(p);
		case  PAP:
			return doPapLogin(p);
		case CHAP:
			return doChapLogin(p);
		case MSCHAPV2:
			return doMsChap2Login(p);
		default:
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.FAIL, 
					FLAG_ZERO,
					"Method not supported",
					"Method not supported"
				);
			
		}
		
	}


	private Packet doChapLogin(AuthenStart p) throws IOException {
		String server_msg = "Wrong user name or password";
		if (user == null || user.trim().isEmpty())
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.FAIL, 
					FLAG_ZERO,
					server_msg,
					""
				);
		byte pppId = p.dataBytes[0];
		byte challenge[] = Arrays.copyOfRange(p.dataBytes, 1, p.dataBytes.length-16);
		byte response[] = Arrays.copyOfRange(p.dataBytes, p.dataBytes.length-16, p.dataBytes.length);
		
		authenticationContext = new AuthenticationContext();
		try {
			authenticationContext.initializeTacacsCtx(user, rem_addr, tacacs.getServiceProvider().getPublicId());
			final ServerService serverService = new RemoteServiceLocator().getServerService();
			account = serverService.getAccountInfo(user, 
					tacacs.getServiceProvider().getSystem());
			Password pass = serverService.getAccountPassword(account.getName(), account.getSystem());

			if (pass != null) {
				if (checkChap (pppId, pass, challenge, response)) { 
					authenticationContext.authenticated(user, "P", null);
					if (authenticationContext.isFinished()) {
						if (new AuthorizationChecker().hasSecurityLevel(p.priv_lvl, user, tacacs.getServiceProvider().getSystem()))
							return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
								TAC_PLUS.AUTHEN.STATUS.PASS, 
								FLAG_ZERO,
								"",
								""
								);
						else
							return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
									TAC_PLUS.AUTHEN.STATUS.FAIL, 
									FLAG_ZERO,
									"Not authorized to privilege level "+privilegeLevel,
									""
									);
					} else {
						server_msg = "MFA not supported by TACACS+ CHAP protocol";
						authenticationContext.authenticationFailure(user, server_msg);
					}
				} else {
					authenticationContext.authenticationFailure(user, "Wrong password (CHAP)");
				}
			} else {
				authenticationContext.authenticationFailure(user, "Password not available in clear text (CHAP)");
			}
		} catch (Exception e) {
			log.warn("Error authenticating "+user+": "+SoffidStackTrace.generateShortDescription(e));
		}
		return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
				TAC_PLUS.AUTHEN.STATUS.FAIL, 
				FLAG_ZERO,
				server_msg,
				""
				);
	}

	private Packet doMsChap2Login(AuthenStart p) throws IOException {
		if (user == null || user.trim().isEmpty())
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.FAIL, 
					FLAG_ZERO,
					"Wrong user name or password",
					""
				);
		byte pppId = p.dataBytes[0];
		byte challenge[] = Arrays.copyOfRange(p.dataBytes, 1, p.dataBytes.length-49);
		byte response[] = Arrays.copyOfRange(p.dataBytes, p.dataBytes.length-49, p.dataBytes.length);
		
		authenticationContext = new AuthenticationContext();
		try {
			authenticationContext.initializeTacacsCtx(user, rem_addr, tacacs.getServiceProvider().getPublicId());
			final ServerService serverService = new RemoteServiceLocator().getServerService();
			account = serverService.getAccountInfo(user, 
					tacacs.getServiceProvider().getSystem());
			Password pass = serverService.getAccountPassword(account.getName(), account.getSystem());

			if (pass != null) {
				if (MSCHAP.verifyMSCHAPv2(user.getBytes(StandardCharsets.UTF_8), pass.getPassword().getBytes(StandardCharsets.UTF_8), challenge, response))  {
					authenticationContext.authenticated(user, "P", null);
					if (authenticationContext.isFinished()) {
						if (new AuthorizationChecker().hasSecurityLevel(p.priv_lvl, user, tacacs.getServiceProvider().getSystem()))
							return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
								TAC_PLUS.AUTHEN.STATUS.PASS, 
								FLAG_ZERO,
								"",
								""
								);
						else
							return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
									TAC_PLUS.AUTHEN.STATUS.FAIL, 
									FLAG_ZERO,
									"Not authorized to privilege level "+privilegeLevel,
									""
									);
					} else {
						authenticationContext.authenticationFailure(user, "MFA not supported by TACACS+ CHAP protocol");
					}
				} else {
					authenticationContext.authenticationFailure(user, "Wrong password (MSCHAPv2)");
				}
				
			} else {
				authenticationContext.authenticationFailure(user, "Password not available in clear text (CHAP)");
			}
		} catch (Exception e) {
			log.warn("Error authenticating "+user+": "+SoffidStackTrace.generateShortDescription(e));
		}
		return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
				TAC_PLUS.AUTHEN.STATUS.FAIL, 
				FLAG_ZERO,
				"Wrong user name or password",
				""
				);
	}

	private boolean checkChap(byte pppId, Password pass, byte[] challenge, byte[] response) {
		MessageDigest md5 = getMd5Digest();
	    md5.reset();
	    md5.update(pppId);
	    md5.update(pass.getPassword().getBytes(StandardCharsets.UTF_8));
	    byte[] hash = md5.digest(challenge);

	    boolean ok = true;
	    for (int i = 0; i < 16; i++)
	    	if (hash[i] != response[i])
	    		return false;
	    return true;
	}


	private Packet doPapLogin(AuthenStart p) throws IOException {
		if (user == null || user.trim().isEmpty())
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.FAIL, 
					FLAG_ZERO,
					"Wrong user name or password",
					""
				);
		String password = p.dataString;
		authenticationContext = new AuthenticationContext();
		try {
			authenticationContext.initializeTacacsCtx(user, rem_addr, tacacs.getServiceProvider().getPublicId());
			account = new RemoteServiceLocator().getServerService().getAccountInfo(user, 
					tacacs.getServiceProvider().getSystem());
			if (validatePassword(password)) {
				if (authenticationContext.isFinished()) {
					if (new AuthorizationChecker().hasSecurityLevel(p.priv_lvl, user, tacacs.getServiceProvider().getSystem()))
						return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
									TAC_PLUS.AUTHEN.STATUS.PASS, 
									FLAG_ZERO,
									"",
									""
									);
					else
						return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
								TAC_PLUS.AUTHEN.STATUS.FAIL, 
								FLAG_ZERO,
								"Not authorized to privilege level "+privilegeLevel,
								""
								);
				} else {
					authenticationContext.authenticationFailure(user, "MFA not supported in TACACS+ PAP protocol");
				}
			} else {
				authenticationContext.authenticationFailure(user, "Wrong password");
			}
		} catch (Exception e) {
			log.warn("Error authenticating "+user+": "+SoffidStackTrace.generateShortDescription(e));
		}
		return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
				TAC_PLUS.AUTHEN.STATUS.FAIL, 
				FLAG_ZERO,
				"Wrong user name or password",
				""
				);
	}


	private boolean validatePassword(String password) throws InternalErrorException, IOException, InvalidPasswordException, UnknownUserException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		boolean ok;
		Set<String> type = authenticationContext.getNextFactor();
		if (type.contains("P")) {
			ok = processPasswordAuth(password);
			if (ok)
				authenticationContext.authenticated(user, "P", null);
		}
		else if (type.contains("O") || type.contains("M") || type.contains("S") || type.contains("I")) {
			ok = processOtp (password);
			if (ok)
				authenticationContext.authenticated(user, "O", null);
		}
		else {
			log.warn("Unable to authenticate using mechanism "+authenticationContext.getAllowedAuthenticationMethods());
			ok = false;
		}
		return ok;
	}


	private boolean processOtp(String password) throws InternalErrorException, IOException {
		OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
		return v.validatePin(authenticationContext.getChallenge(), password);
	}


	private boolean processPasswordAuth(String password) throws RemoteException, FileNotFoundException, IOException, InternalErrorException, InvalidPasswordException, UnknownUserException {
        PasswordManager v = new PasswordManager();
        return v.validate(user, new Password(password));
	}


	private Packet doInteractiveLogin(Packet p) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		// Fetch login data
		
		if (p instanceof AuthenStart) {
			user = ((AuthenStart) p).username;
		}
		else {
			AuthenContinue c = (AuthenContinue) p;
			if (user == null || user.trim().isEmpty())
				user = c.user_msg;
			else if (authenticationContext == null) {
				if (c.user_msg != null && !c.user_msg.trim().isEmpty())
					password = new Password( c.user_msg );
			}
			else if (authenticationContext.getNextFactor().contains("P") && password == null) {
				if (c.user_msg != null && !c.user_msg.trim().isEmpty())
					password = new Password( c.user_msg );
			} 
			else if (authenticationContext.getNextFactor().contains("P") && newPassword == null && changingPassword) {
				if (c.user_msg != null && !c.user_msg.trim().isEmpty())
					newPassword = new Password( c.user_msg );
			} else {
				if (c.user_msg != null && !c.user_msg.trim().isEmpty())
					otp = new Password( c.user_msg );
			}
		}
		
		// Process login
		
		if (user == null || user.trim().isEmpty())
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETUSER, 
					FLAG_ZERO,
					"User name: ",
					""
				);
		else if (authenticationContext == null && password == null) {
			authenticationContext = new AuthenticationContext();
			try {
				authenticationContext.initializeTacacsCtx(user, rem_addr, tacacs.getServiceProvider().getPublicId());
				account = new RemoteServiceLocator().getServerService().getAccountInfo(user, 
						tacacs.getServiceProvider().getSystem());
			} catch (Exception e) {
				return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
						TAC_PLUS.AUTHEN.STATUS.GETPASS, 
						(byte) 1,
						"Password: ",
						""
						);
			}
		}
		else if (authenticationContext == null || account == null || account.isDisabled()) {
			return failMessage(p);
		}
		
		Set<String> nf = authenticationContext.getNextFactor();
		if (changingPassword) {
			if (newPassword != null) {
				new RemoteServiceLocator().getUserBehaviorService().changePassword(tacacs.getServiceProvider(), account.getName(), password, newPassword);
				authenticationContext.authenticated(authenticationContext.getUser(), "P", null);
				changingPassword = false;
			}
		}
		else if (nf.contains("P") && password != null) {
			PasswordValidation r = new RemoteServiceLocator().getUserBehaviorService().validatePassword(tacacs.getServiceProvider(), account.getName(), password);
			if (r == PasswordValidation.PASSWORD_GOOD_EXPIRED) {
				changingPassword = true;
			}
			else if (r == PasswordValidation.PASSWORD_GOOD) {
				authenticationContext.authenticated(authenticationContext.getUser(), "P", null);
			}
			else
			{
				authenticationContext.authenticationFailure(authenticationContext.getUser(), "Wrong password");
				return failMessage(p);
			}
		}
		else if (otp != null && (nf.contains("O") || nf.contains("M") || nf.contains("I") || nf.contains("S"))) {
			OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
			if (v.validatePin(authenticationContext.getChallenge(), otp.getPassword())) {
				authenticationContext.authenticated(authenticationContext.getUser(), "O", null);
			} else {
				authenticationContext.authenticationFailure(authenticationContext.getUser(), "Wrong OTP PIN");
				return failMessage(p);
			}
		}
		
		Set<String> nextFactors = authenticationContext.getNextFactor();
		
		if (authenticationContext != null && authenticationContext.isFinished()) {
			if (new AuthorizationChecker().hasSecurityLevel(privilegeLevel, user, tacacs.getServiceProvider().getSystem()))
				return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.PASS, 
					FLAG_ZERO,
					"",
					""
					);
			else
				return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
						TAC_PLUS.AUTHEN.STATUS.FAIL, 
						FLAG_ZERO,
						"Not authorized to privilege level "+privilegeLevel,
						""
						);
		} else if (user == null || user.trim().isEmpty()) {
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETUSER, 
					FLAG_ZERO,
					"User name: ",
					""
					);
		} else if (changingPassword) {
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETPASS, 
					(byte) 1,
					"New password: ",
					""
					);
		} else if (authenticationContext == null || nextFactors.contains("P")) {
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETPASS, 
					(byte) 1,
					"Password: ",
					""
					);
		} else if (nextFactors.contains("O") || nextFactors.contains("M") || nextFactors.contains("I")|| nextFactors.contains("S")) {
			Challenge ch = new Challenge();
			ch.setUser(authenticationContext.getCurrentUser());
			StringBuffer otpType = new StringBuffer();
			if (nf.contains("O")) otpType.append("OTP ");
			if (nf.contains("M")) otpType.append("EMAIL ");
			if (nf.contains("I")) otpType.append("PIN ");
			if (nf.contains("S")) otpType.append("SMS ");
			ch.setOtpHandler(otpType.toString());
			OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
			ch = v.selectToken(ch);
			authenticationContext.setChallenge(ch);
			if (ch.getCardNumber() != null)
			{
				return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
						TAC_PLUS.AUTHEN.STATUS.GETPASS, 
						(byte) 1,
						ch.getCardNumber()+" "+ch.getCell(),
						""
						);
				
			} else {
				return failMessage(p);
			}
		} else {
			return failMessage(p);
		}
	}

	private Packet failMessage(Packet p) throws IOException {
		return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
				TAC_PLUS.AUTHEN.STATUS.FAIL, 
				FLAG_ZERO,
				"Wrong user name or password",
				"Wrong user name or password"
				);
	}
		
	private Packet errorMessage(Packet p) throws IOException {
		return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
				TAC_PLUS.AUTHEN.STATUS.FAIL, 
				FLAG_ZERO,
				"Protocol not supported",
				"Protocol not supported"
				);
	}
		
		
	private Packet doInteractiveChangePassword(Packet p) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		// Fetch data
		if (p instanceof AuthenStart) {
			user = ((AuthenStart)p).username;
		} else {
			AuthenContinue c = (AuthenContinue) p;
			if (user == null || user.trim().isEmpty()) {
				user = c.user_msg;
			} else if (oldPassword == null) {
				if (c.user_msg != null && !c.user_msg.trim().isEmpty())
					oldPassword = new Password(c.user_msg);
			} else if (step == 3) {
				if (c.user_msg != null && !c.user_msg.trim().isEmpty())
					newPassword = new Password(c.user_msg);
			} else if (step == 4) {
				if (c.user_msg != null && !c.user_msg.trim().isEmpty())
					newPassword2 = new Password(c.user_msg);
			}
		}
		
		// Ask for user_msg or process
		if (user == null || user.trim().isEmpty())
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETUSER, 
					FLAG_ZERO,
					"User name",
					""
				);
		else if (oldPassword == null)
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETDATA, 
					FLAG_ZERO,
					"Current password",
					""
				);
		else if (newPassword == null) 
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETDATA, 
					FLAG_ZERO,
					"New password",
					""
				);
		else if (newPassword == null) 
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETDATA, 
					FLAG_ZERO,
					"Repeat new password",
					""
				);
		else {
			authenticationContext = new AuthenticationContext();
	
			try {
				authenticationContext.initializeTacacsCtx(user, rem_addr, tacacs.getServiceProvider().getPublicId());
				account = new RemoteServiceLocator().getServerService().getAccountInfo(user, 
						tacacs.getServiceProvider().getSystem());
			} catch (Exception e) {
				return failMessage(p);
				
			}
			// Not authorized --> To fail later
			if (account == null || account.isDisabled())
				return failMessage(p);
			Set<String> nf = authenticationContext.getNextFactor();
			if (! nf.contains("P")) {
				return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.AUTHEN.STATUS.FAIL, 
							FLAG_ZERO,
							"Password authentication method is disabled",
							"Password authentication method is disabled"
						);
			}

			new RemoteServiceLocator().getUserBehaviorService().changePassword(tacacs.getServiceProvider(), account.getName(), oldPassword, newPassword);

			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.PASS, 
					FLAG_ZERO,
					"",
					""
					);
		}
	}
	
	protected MessageDigest getMd5Digest() {
		if (md5Digest == null)
			try {
				md5Digest = MessageDigest.getInstance("MD5");
			} catch (NoSuchAlgorithmException nsae) {
				throw new RuntimeException("md5 digest not available", nsae);
			}
		return md5Digest;
	}

}