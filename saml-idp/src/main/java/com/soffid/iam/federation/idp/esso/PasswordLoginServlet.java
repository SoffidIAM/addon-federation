package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.security.PrivilegedAction;
import java.sql.Timestamp;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;

import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.esso.OtpSelector;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.System;
import com.soffid.iam.api.User;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.sync.service.LogonService;
import com.soffid.iam.sync.service.SecretStoreService;
import com.soffid.iam.sync.service.ServerService;
import com.soffid.iam.utils.ConfigurationCache;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.BadPasswordException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.InvalidPasswordException;
import es.caib.seycon.ng.exception.LogonDeniedException;
import es.caib.seycon.util.Base64;

public class PasswordLoginServlet extends HttpServlet {

    public PasswordLoginServlet() {
    }

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    Log log = LogFactory.getLog("PasswordLoginServlet");

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
            IOException {
        resp.setContentType("text/plain; charset=UTF-8");
        String action = req.getParameter("action");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                "UTF-8"));
        try {
            if ("prestart".equals(action))
                writer.write(doPreStartAction(req, resp));
            else if ("start".equals(action))
                writer.write(doStartAction(req, resp));
            else if ("changePass".equals(action))
                writer.write(doChangePassAction(req, resp));
            else if ("getSecrets".equals(action))
                writer.write(doSecretsAction(req, resp));
            else if ("createSession".equals(action))
                writer.write(doCreateSessionAction(req, resp));
            else if ("joinSession".equals(action))
                writer.write(doJoinSessionAction(req, resp));
            else
                throw new Exception("Invalid action " + action);
        } catch (Exception e) {
            log.warn("Error performing password login", e);
            StringBuffer b = new StringBuffer().append (e.getClass().getName()).
            				append ("|").
            				append (e.getMessage()).
            				append ("\n");
            writer.write(b.toString());
        }
        writer.close();

    }

    private String doChangePassAction(HttpServletRequest req, HttpServletResponse resp) throws InternalErrorException {
        String user = req.getParameter("user");
        String domain = req.getParameter("domain");
        String pass1 = req.getParameter("password1");
        String pass2 = req.getParameter("password2");

        try {
	    	if (domain.isEmpty() )
	    		domain = null;
	    	else if (domain != null)
	        {
	    		ServerService ss = new RemoteServiceLocator().getServerService();
	        	System dispatcher = ss.getDispatcherInfo(domain);
	        	if (!ss.getDefaultDispatcher().equals (domain) &&
	        		! dispatcher.getTrusted().booleanValue() )
	        	{
	        		return "ERROR|" + String.format("'%s' is not a trusted Soffid Agent", domain);
	        	}
	        }

            new RemoteServiceLocator().getLogonService().changePassword(user, domain, pass1, pass2);
        } catch (IOException e) {
            return "ERROR|" + e.toString();
        } catch (InternalErrorException e) {
            return "ERROR|" + e.toString();
        } catch (BadPasswordException e) {
            return "ERROR2|" + e.getMessage();
        } catch (InvalidPasswordException e) {
            return "ERROR1|" + e.toString();
        }
        return "OK";

    }

    private String doCreateSessionAction(HttpServletRequest req, HttpServletResponse resp)
            throws InternalErrorException, IOException {
        Challenge challenge = getChallenge(req);

        try {
            String value = req.getParameter("cardValue");
            String port = req.getParameter("port");
            challenge.setCloseOldSessions("true".equals(req.getParameter("force")));
            challenge.setSilent("true".equals(req.getParameter("silent")));
            challenge.setValue(value);
            challenge.setCentinelPort(Integer.decode(port));
            UserCredentialChallenge ucch = (UserCredentialChallenge) challenge.getAdditionalData();
            if (ucch != null && 
            		! new RemoteServiceLocator()
            		.getPushAuthenticationService()
            		.isPushAuthenticationAccepted(ucch)) {
                return "WAIT|"+ucch.getImageUrl();
            }
            Session s = new RemoteServiceLocator().getLogonService().responseChallenge(challenge);

            boolean canAdmin;

            Host maquinaAcces = new RemoteServiceLocator().getServerService().getHostInfoByIP(com.soffid.iam.utils.Security.getClientIp());
            canAdmin = new RemoteServiceLocator().getServerService().hasSupportAccessHost(maquinaAcces.getId(), challenge.getUser().getId());

            return "OK|" + challenge.getChallengeId() + "|" + Long.toString(s.getId())
                    + "|" + canAdmin;
        } catch (Exception e) {
        	log.warn("Error authenticating user", e);
            return e.getClass().getName() + "|" + e.getMessage() + "\n";
        }
    }

    private String doJoinSessionAction(HttpServletRequest req, HttpServletResponse resp)
            throws InternalErrorException {
        try {
            String sessionId = req.getParameter("sessionId");
            String sessionKey = req.getParameter("sessionKey");
            String port = req.getParameter("port");

            SessionService sessioService = new RemoteServiceLocator().getSessionService();
            
            Session s = sessioService.joinEssoSession(Long.decode(sessionId), sessionKey, Integer.decode(port));
            if (s != null) {
            	ServerService serverService = new RemoteServiceLocator().getServerService();
            	User u = serverService.getUserInfo(s.getUserName(), null); 
            	
            	Host maquinaAcces = serverService.getHostInfoByIP(com.soffid.iam.utils.Security.getClientIp());
            	boolean canAdmin = serverService.hasSupportAccessHost(maquinaAcces.getId(), u.getId());
            	
            	// Store temporary challenge
            	Challenge challenge = new Challenge();
            	challenge.setUser(u);
            	challenge.setCentinelPort(Integer.decode(port));
            	challenge.setChallengeId(sessionKey);
            	challenge.setTimeStamp(new Timestamp(java.lang.System.currentTimeMillis()));
            	challengeStore.store(challenge);
            	return "OK|" + sessionKey + "|" + Long.toString(s.getId())
            	+ "|" + canAdmin;
            } else {
            	return "ERROR|Wrong challenge id";
            }
        } catch (Exception e) {
            return e.getClass().getName() + "|" + e.getMessage() + "\n";
        }
    }

    private String doSecretsAction(HttpServletRequest req, HttpServletResponse resp)
            throws InternalErrorException, IOException {
    	boolean encode = "true".equals( req.getParameter("encode") );
        final Challenge challenge = getChallenge(req);
        if (challenge == null)
            return "ERROR|Unknown ticket";
        else {
        	challengeStore.removeChallenge(challenge);
            return dumpSecrets(encode, challenge.getChallengeId(), challenge.getUser());
        }
    }

	protected String dumpSecrets(boolean encode, String sessionKey, final User user)
			throws InternalErrorException, IOException {
		StringBuffer result = new StringBuffer("OK");
		
		for (Secret secret: new RemoteServiceLocator().getSecretStoreService().getAllSecrets(user)) {
			if (secret.getName() != null && secret.getName().length() > 0 &&
					secret.getValue() != null &&
					secret.getValue().getPassword() != null &&
					secret.getValue().getPassword().length() > 0 )
			{
		        result.append('|');
		        if (encode)
		        	result.append( encodeSecret(secret.getName()));
		        else
		        	result.append(secret.getName());
		        result.append('|');
		        if (encode)
		            result.append( encodeSecret(secret.getValue().getPassword()));
		        else
		        	result.append(secret.getValue().getPassword());
			}
		}
		result.append ("|sessionKey|").append(sessionKey);
		if (encode)
			result.append ("|fullName|").append(encodeSecret(user.getFullName()));
		else
			result.append ("|fullName|").append(user.getFullName());
		return result.toString();
	}

	private String encodeSecret(String secret)
			throws UnsupportedEncodingException {
		return URLEncoder.encode(secret,"UTF-8").replaceAll("\\|", "%7c"); 
	}

    private static ChallengeStore challengeStore = ChallengeStore.getInstance();

    private String doStartAction(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String s = doPreStartAction(req, resp);
    	if (s.equals("OK")) {
            String clientIP = req.getParameter("clientIP");
            String domain = req.getParameter("domain");
            String text = req.getParameter("textPush");
            if (domain.isEmpty())
            	domain = null;
            String user = req.getParameter("user");
            String hostSerial=req.getParameter("serial");

            String cardSupport = req.getParameter("cardSupport");
            String hostIP = com.soffid.iam.utils.Security.getClientIp();
            int iCardSupport = Challenge.CARD_IFNEEDED;
            try {
                iCardSupport = Integer.decode(cardSupport);
            } catch (Exception e) {
            }

            Challenge challenge = new RemoteServiceLocator().getLogonService()
            		.requestIdpChallenge(Challenge.TYPE_PASSWORD, user, domain, 
            		hostSerial == null ? hostIP: hostSerial, clientIP,
                    iCardSupport,
                    IdpConfig.getConfig().getPublicId());
            
            challenge = new RemoteServiceLocator().getEssoService()
            		.updateAndRegisterChallenge(challenge, "true".equals(text));
            if ( challenge == null ) {
            	throw new LogonDeniedException("Access is not allowed");
            }
            challengeStore.store(challenge);

            return "OK|" + challenge.getChallengeId() + "|" + challenge.getCardNumber() + "|"
                    + challenge.getCell()+"|"+challenge.getUser().getUserName();

        } else
            return s;
    }

    private String doPreStartAction(HttpServletRequest req, HttpServletResponse resp)
            throws Exception {
        String user = req.getParameter("user");
        String domain = req.getParameter("domain");
        String pass = req.getParameter("password");
        
        ServerService serverService = new RemoteServiceLocator().getServerService();
        LogonService logonService = new RemoteServiceLocator().getLogonService();
        
    	if (domain.isEmpty() )
    		domain = null;
    	else if (domain != null)
        {
        	System dispatcher = serverService.getDispatcherInfo(domain);
        	if (!serverService.getDefaultDispatcher().equals (domain) &&
        		! dispatcher.getTrusted().booleanValue() )
        	{
        		return "ERROR|" + String.format("'%s' is not a trusted Soffid Agent", domain);
        	}
        }
        User usuari = serverService.getUserInfo(user, domain);

        PasswordValidation result = logonService.validatePassword(user, domain, pass);
        if (result == PasswordValidation.PASSWORD_GOOD) {
        	log.info("Prestart action GOOD "+user+" "+domain);
            if (! usuari.getActive().booleanValue()) {
                log.info("login "+user+" is disabled: not authorized");
                return "ERROR";
            }
        } else if (result == PasswordValidation.PASSWORD_GOOD_EXPIRED) {
            log.info("login "+user+": password expired");
            return "EXPIRED";
        } else {
            log.info("login "+user+": not valid");
            return "ERROR";
        }

        return "OK";

    }

    private Challenge getChallenge(HttpServletRequest req) throws InternalErrorException, IOException {
        String challengeId = req.getParameter("challengeId");
        final Challenge challenge = challengeStore.getChallenge(challengeId);

        if (challenge == null)
            throw new InternalErrorException("Invalid token " + challengeId);
        return challenge;
    }

}
