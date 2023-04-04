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
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iad.addons.federation.idp.tacacs.impl.AuthenticationHandler;
import com.soffid.iam.addons.federation.idp.radius.server.RadiusException;
import com.soffid.iam.addons.federation.idp.radius.server.RadiusUtil;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Password;
import com.soffid.iam.service.OTPValidationService;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.server.AuthenticationContext;
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
								"Wrong authentiaciton package."
							);

				}
				tacacs.write(r);
				end(r);
				break;
			case AUTHOR:
				r = new AuthorReply
				(
					p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHOR.STATUS.FAIL, 
					"The AUTHORIZATION operation is not implemented.",
					"The AUTHORIZATION operation is not implemented.",
					null
				);
				tacacs.write(r);
				end(r);
				break;
			case ACCT:
				r = new AcctReply
				(
					p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.ACCT.STATUS.ERROR, 
					"The ACCOUNTING operation is not implemented.",
					"The ACCOUNTING operation is not implemented."
				);
				tacacs.write(r);
				end(r);
				break;
		}
	}


	private Packet handleAuthenticationContinue(AuthenContinue p) {
	}


	private Packet handleAuthenticationStart(AuthenStart p) throws InternalErrorException, IOException {
		this.user = p.username;
		switch (p.action) {
		case LOGIN:
			return handleAuthenticationStartLogin(p);
		case CHPASS:
			return handleChangePassword(p);
		case SENDAUTH:
			return handleSendAuthorization(p);
		}
	}


	private Packet handleSendAuthorization(AuthenStart p) {
		// TODO Auto-generated method stub
		return null;
	}


	private Packet handleChangePassword(AuthenStart p) {
		// TODO Auto-generated method stub
		return null;
	}


	private Packet handleAuthenticationStartLogin(AuthenStart p) {
		switch ( authen_svc ) {
		case NONE:
			return new AuthenReply
						(
							p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.AUTHEN.STATUS.PASS, 
							FLAG_ZERO,
							"",
							""
						);
		case ENABLE:
			return new AuthenReply
					(
						p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
						TAC_PLUS.AUTHEN.STATUS.FAIL, 
						FLAG_ZERO,
						"Not supported",
						"Net supported"
					);
		default:
			return doLogin(p);
		}
	}


	private Packet doLogin(AuthenStart p) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		switch (p.type) {
		case ASCII: 
			interactiveLogin = true;
			return doInteractiveLogin(p);
		case  PAP:
			return dePapLogin(p);
		case CHAP:
			return doChapLogin(p);
		}
		
	}


	private Packet doChapLogin(AuthenStart p) throws IOException {
		if (user == null || user.trim().isEmpty())
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.FAIL, 
					FLAG_ZERO,
					"Wrong user name or password",
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
				if (checkChap (pppId, pass, challenge, response)) 
					return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
							TAC_PLUS.AUTHEN.STATUS.PASS, 
							FLAG_ZERO,
							"",
							""
							);
				
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


	private Packet dePapLogin(AuthenStart p) throws IOException {
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
			if (validatePassword(password) && authenticationContext.isFinished()) {
				return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
						TAC_PLUS.AUTHEN.STATUS.PASS, 
						FLAG_ZERO,
						"",
						""
					);
				
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
		if (user == null || user.trim().isEmpty())
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
					TAC_PLUS.AUTHEN.STATUS.GETUSER, 
					FLAG_ZERO,
					"User name",
					""
				);
		authenticationContext = new AuthenticationContext();
		try {
			authenticationContext.initializeTacacsCtx(user, rem_addr, tacacs.getServiceProvider().getPublicId());
			account = new RemoteServiceLocator().getServerService().getAccountInfo(user, 
					tacacs.getServiceProvider().getSystem());
		} catch (Exception e) {
			// Not authorized --> To fail later
		}
		
		Set<String> nf = authenticationContext.getNextFactor();
		if (nf.contains("P"))
			return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
						TAC_PLUS.AUTHEN.STATUS.GETPASS, 
						FLAG_ZERO,
						"Password",
						""
					);
		if (nf.contains("O") || nf.contains("M") || nf.contains("I") || nf.contains("S")) {
			OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
			
			Challenge ch = new Challenge();
			ch.setUser(authenticationContext.getCurrentUser());
			StringBuffer otpType = new StringBuffer();
			if (nf.contains("O")) otpType.append("OTP ");
			if (nf.contains("M")) otpType.append("EMAIL ");
			if (nf.contains("I")) otpType.append("PIN ");
			if (nf.contains("S")) otpType.append("SMS ");
			ch.setOtpHandler(otpType.toString());
			ch = v.selectToken(ch);
			authenticationContext.setChallenge(ch);
			if (ch.getCardNumber() != null)
			{
				return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
						TAC_PLUS.AUTHEN.STATUS.GETPASS, 
						FLAG_ZERO,
						ch.getCardNumber()+" "+ch.getCell(),
						""
					);
		
			}
		}
		
		return new AuthenReply	(p.getHeader().next(TAC_PLUS.PACKET.VERSION.v13_0), 
				TAC_PLUS.AUTHEN.STATUS.GETPASS, 
				FLAG_ZERO,
				"Password",
				""
			);
		
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