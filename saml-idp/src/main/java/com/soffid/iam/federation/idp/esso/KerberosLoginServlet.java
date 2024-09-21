package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.sync.service.LogonService;
import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.utils.Security;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.LogonDeniedException;

public class KerberosLoginServlet extends HttpServlet {
    public KerberosLoginServlet() {
    }

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    org.apache.commons.logging.Log log = LogFactory.getLog(getClass());

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
    IOException {
    	resp.getOutputStream().println("OK");
    }
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
            IOException {
        String action = req.getParameter("action");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                "UTF-8"));
        try {
            if ("start".equals(action))
                writer.write(doStartAction(req, resp));
            else if ("continue".equals(action))
                writer.write(doContinueAction(req, resp));
            else if ("pbticket".equals(action))
                writer.write(doPBAction(req, resp));
            else if ("getSecrets".equals(action))
                writer.write(doSecretsAction(req, resp));
            else if ("createSession".equals(action))
                writer.write(doCreateSessionAction(req, resp));
            else {
            	resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } catch (Exception e) {
            log.warn("Error performing kerberos login", e);
            writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
        }
        writer.close();
    }

    private String doCreateSessionAction(HttpServletRequest req, HttpServletResponse resp)
            throws InternalErrorException, IOException {
        Challenge challenge = getChallenge(req);

        try {
            String value = req.getParameter("cardValue");
            String port = req.getParameter("port");
            UserCredentialChallenge ucch = (UserCredentialChallenge) challenge.getAdditionalData();
            if (ucch != null && 
            		! new RemoteServiceLocator()
            		.getPushAuthenticationService()
            		.isPushAuthenticationAccepted(ucch)) {
                return "WAIT|"+ucch.getImageUrl();
            }
            challenge.setCloseOldSessions("true".equals(req.getParameter("force")));
            challenge.setSilent("true".equals(req.getParameter("silent")));
            challenge.setValue(value);
            challenge.setCentinelPort(Integer.decode(port));
            Session result = new RemoteServiceLocator().getLogonService().responseChallenge(challenge);

            return "OK|" + challenge.getChallengeId() + "|" + Long.toString(result.getId()) + "|";
        } catch (Exception e) {
            log.warn("Error creating session", e);
            return e.getClass().getName() + "|" + e.getMessage() + "\n";
        }
    }

    private String doPBAction(HttpServletRequest req, HttpServletResponse resp)
            throws InternalErrorException, IOException {
        String challengeId = req.getParameter("challengeId");

        final Challenge challenge = challengeStore.getChallenge(challengeId);
        if (challenge == null)
            return "ERROR|Ticket unknown " + challengeId;
        else {
            String ticket = null;
            challengeStore.removeChallenge(challenge);
            return "OK|" + ticket;
        }
    }

    private String doSecretsAction(HttpServletRequest req, HttpServletResponse resp)
            throws InternalErrorException, IOException {
    	boolean encode = "true".equals( req.getParameter("encode") );
        final Challenge challenge = getChallenge(req);
        if (challenge == null)
            return "ERROR|Unknown ticket";
        else {
            StringBuffer result = new StringBuffer("OK");
            
            for (Secret secret: new RemoteServiceLocator().getSecretStoreService().getAllSecrets(challenge.getUser())) {
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
            result.append ("|sessionKey|").append(challenge.getChallengeId());
            if (encode)
            	result.append ("|fullName|").append(encodeSecret(challenge.getUser().getFullName()));
            else
            	result.append ("|fullName|").append(challenge.getUser().getFullName());
            challengeStore.removeChallenge(challenge);
            return result.toString();
        }
    }

	private String encodeSecret(String secret)
			throws UnsupportedEncodingException {
		return URLEncoder.encode(secret,"UTF-8").replaceAll("\\|", "%7c"); 
	}

    private static ChallengeStore challengeStore = ChallengeStore.getInstance();

    private String doStartAction(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String clientIP = req.getParameter("clientIP");
        String cardSupport = req.getParameter("cardSupport");
        String hostIP = Security.getClientIp();
        String hostSerial=req.getParameter("serial");
        String text = req.getParameter("textPush");

        String principal = req.getRemoteUser();
        if (principal == null)
        {
        	return "ERROR|Not authorized";
        }
        int split = principal.lastIndexOf('@');
        if (split < 0)
        {
        	resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        	log.info("Unknown principal "+principal);
        	return "ERROR|Not authorized";
        }
        String user = principal.substring(0, split);
        String system = principal.substring(split + 1);

        
        LogonService logonService = new RemoteServiceLocator().getLogonService();

        final Challenge challenge = 
        		logonService.requestIdpChallenge(Challenge.TYPE_KERBEROS, 
        				system == null ? principal: user,
        				system, 
        				hostSerial == null ? hostIP: hostSerial, clientIP,
        				Integer.decode(cardSupport),
        				IdpConfig.getConfig().getPublicId());

        if ( ! new RemoteServiceLocator().getEssoService()
        		.updateAndRegisterChallenge(challenge, "true".equals(text))) {
        	throw new LogonDeniedException("Access is not allowed");
        }
        // Check some credentials are stored
        if ( new RemoteServiceLocator().getSecretStoreService().getAllSecrets(challenge.getUser()).isEmpty()) {
        	throw new LogonDeniedException("No secrets available for "+user+" yet");
        }


        return tryLogin(challenge, req);

    }

    private String doContinueAction(HttpServletRequest req, HttpServletResponse resp)
            throws Exception {
        final Challenge challenge = getChallenge(req);
        String token = req.getParameter("krbToken");

        return tryLogin(challenge, req);

    }

    private Challenge getChallenge(HttpServletRequest req) throws InternalErrorException, IOException {
        String challengeId = req.getParameter("challengeId");
        final Challenge challenge = challengeStore.getChallenge(challengeId);

        if (challenge == null)
            throw new InternalErrorException("Invalid token " + challengeId);
        boolean trackIp = "true".equals( ConfigurationCache.getProperty("SSOTrackHostAddress"));
        if ( trackIp && !challenge.getHost().getIp().equals(Security.getClientIp())) 
        {
            log.warn("Ticket spoofing detected from "+Security.getClientIp()+". Expected "+challenge.getHost().getIp());
            throw new InternalErrorException("Invalid token " + challengeId);
        }
        return challenge;
    }

    private String tryLogin(final Challenge challenge, final HttpServletRequest req) throws Exception {
    	return "OK|" + challenge.getChallengeId() + "||"
               + challenge.getCardNumber() + "|" + challenge.getCell()+ "|" + challenge.getUser().getUserName();
    }
}
