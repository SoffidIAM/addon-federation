package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.rpc.ServiceException;

import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.util.StreamParsingException;
import org.mortbay.log.Log;
import org.mortbay.log.Logger;

import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.service.LogonService;
import com.soffid.iam.sync.service.SecretStoreService;
import com.soffid.iam.sync.web.NameMismatchException;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.CertificateValidator;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.util.Base64;
import es.caib.signatura.api.SignatureVerifyException;
import es.caib.signatura.utils.BitException;

public class CertificateLoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    Logger log = Log.getLogger("CertificateLoginServlet");
    private X509Certificate userCertificate;
    private X509Certificate[] certificateChain;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String action = req.getParameter("action");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp
                .getOutputStream(), "UTF-8"));
        try {
            if (action == null)
                writer.write(doStartTestAction(req, resp));
            else if ("start".equals(action))
                writer.write(doStartAction(req, resp));
            else if ("continue".equals(action))
                writer.write(doContinueAction(req, resp));
            else
                throw new Exception("Invalid action " + action);
        } catch (Exception e) {
            log.warn("Error performing certificate login", e);
            writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
        }
        writer.close();

    }

    private String doStartTestAction(HttpServletRequest req,
            HttpServletResponse resp) throws Exception {
        StringBuffer buf = new StringBuffer();
        resp.setContentType("text/html; charset='UTF-8'");
        buf.append("<HTML><FORM method='POST' enctype='multipart/form-data' action='/certificateLogin'>");
        buf.append("Sel·leccioni el certificat<br>");
        buf.append("<input type=hidden name='action' value='test'><br>");
        buf.append("<input type=file name=cert><br>");
        buf.append("<input type=submit value=Acceptar></FORM></HTML>");
        return buf.toString();
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
    {
    	doGet(req, resp);
    }
    
    private String doStartAction (HttpServletRequest req,
            HttpServletResponse resp) throws Exception {
        String hostIP = com.soffid.iam.utils.Security.getClientIp();
        SecureRandom random = new SecureRandom();
        
        byte b[] = new byte[32];
       	random.nextBytes(b); 
       	
       	String challenge = Base64.encodeBytes(b, Base64.DONT_BREAK_LINES);
       	challenge = challenge.replace('+', '!');
       	certChallenges.put(challenge, hostIP);
        
        return "OK|" + challenge;
    }

    private String doContinueAction(HttpServletRequest req,
            HttpServletResponse resp) throws Exception {
        final String challenge = getCertChallenge(req);
        certChallenges.remove(challenge);
        final String pkcs7 = req.getParameter("pkcs7");
        if (pkcs7 == null) {
            final String pkcs1 = req.getParameter("signature");
            final String cert = req.getParameter("cert");
            return pkcs1Login(req, challenge, pkcs1, cert);
        } else {
            return pkcs7Login(req, challenge, pkcs7);
        }

    }

    private String pkcs1Login(HttpServletRequest req, String challenge, String pkcs1, String cert) throws StreamParsingException, InternalErrorException, CertificateEncodingException, ServiceException, UnknownUserException, IOException {
        byte certBytes[] = Base64.decode(cert);
        X509CertParser parser = new X509CertParser();
        Vector v = new Vector();
        parser.engineInit(new ByteArrayInputStream(certBytes));
        X509Certificate x509Cert = (X509Certificate) parser.engineRead();
        while (x509Cert != null)
        {
            v.add(x509Cert);
            x509Cert = (X509Certificate) parser.engineRead();
        }
        certificateChain = (X509Certificate[]) v.toArray(new X509Certificate[v.size()]);
        userCertificate = certificateChain[0];
        if (!verifySignaturePKCS1(challenge, pkcs1))
            return "ERROR|Wrong signature";
        CertificateValidator mgr = new CertificateValidator();
        String user = mgr.validate(certificateChain);
        if (user == null)
            return "ERROR|Wrong certificate";
        return getCredentials(req, challenge, user);
    }

    private String pkcs7Login(HttpServletRequest req, final String challenge, final String pkcs7)
            throws InternalErrorException, CertificateEncodingException,
            BitException, RemoteException, ServiceException,
            UnknownUserException, IOException {
        if (!verifySignaturePKCS7(challenge, pkcs7))
            return "ERROR|Wrong signature";
        String user = new CertificateValidator().validate(certificateChain);
        
        if (user == null)
            return "ERROR|Certificate not recognized";
        return getCredentials(req, challenge, user);
    }

    private String getCredentials(HttpServletRequest req, String challenge, String userName)
            throws InternalErrorException, CertificateEncodingException, UnknownUserException, IOException {
        try {
            User user = new RemoteServiceLocator().getServerService().getUserInfo(userName, null);
	    	boolean encode = "true".equals( req.getParameter("encode") );
            StringBuffer result = new StringBuffer("OK");
            SecretStoreService secretStoreService = new RemoteServiceLocator().getSecretStoreService();
            String hostSerial=req.getParameter("serial");
            
            LogonService ls = new RemoteServiceLocator().getLogonService();
            Challenge ch = ls.requestIdpChallenge(Challenge.TYPE_CERT, user.getUserName(), null, 
            		hostSerial == null ? com.soffid.iam.utils.Security.getClientIp() : hostSerial, 
            		"", Challenge.CARD_DISABLED,
            		IdpConfig.getConfig().getPublicId());
            ls.responseChallenge(ch);
            
            for (Secret secret: secretStoreService.getAllSecrets(user)) {
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
            for (UserAccount account: new RemoteServiceLocator().getAccountService().findUsersAccounts(user.getUserName(), "SOFFID"))
            {
	            result.append ("|password|").append(secretStoreService.getPassword( account.getId() ).getPassword());
            }
            result.append ("|sessionKey|").append(ch.getChallengeId());
            if (encode)
            	result.append ("|fullName|").append(encodeSecret(ch.getUser().getFullName()));
            else
            	result.append ("|fullName|").append(ch.getUser().getFullName());
            return result.toString();
	    } catch (NameMismatchException e) {
	        return "ERROR|Certificate name does not match: "
	                + e.getMessage();
	    } catch (Exception e) {
	        return "ERROR|Logon denied: "
	                + e.getMessage();
		}
    }

	private String encodeSecret(String secret)
			throws UnsupportedEncodingException {
		return URLEncoder.encode(secret,"UTF-8").replaceAll("|", "%7c"); 
	}

    @SuppressWarnings("deprecation")
    boolean verifySignaturePKCS7(String key, String pkcs7string)
            throws InternalErrorException {
        boolean verified = true;
        try {
            userCertificate = null;
            certificateChain = null;

            ByteArrayInputStream content = new ByteArrayInputStream(key
                    .getBytes("ISO-8859-1"));
            byte[] pkcs7 = Base64.decode(pkcs7string);
            // Verificación de la firma del documento
            CMSTypedStream typedIn = new CMSTypedStream(content);

            
            CMSSignedDataParser parser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), typedIn, pkcs7);
            CMSTypedStream in = parser.getSignedContent();
            in.drain();

            // Obenir els certificats del PKCS7
            Store certs = parser.getCertificates();

            // Obtenir les dades del primer (i únic) signant
            SignerInformationStore signersStore = parser.getSignerInfos();
            Collection signers = signersStore.getSigners();
            Iterator it = signers.iterator();
            byte[] digest;
            if (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                // Obtenir el certificat del signatari
                Collection certCollection = certs.getMatches(signer
                        .getSID());
                Iterator certIt = certCollection.iterator();
                if (certIt.hasNext()) {
                    userCertificate = (X509Certificate) certIt.next();
                }
                /*
                 * Se recuperan todos los certificados
                 */
                certCollection = certs.getMatches(null);
                certIt = certCollection.iterator();
                LinkedList allCertificates = new LinkedList();
                while (certIt.hasNext()) {
                    allCertificates.addFirst(certIt.next());
                }
                // Se construeix la cadena de certificació.
                X509Certificate currentCertificate = userCertificate;
                LinkedList certificateChainList = new LinkedList();
                certificateChainList.addFirst(userCertificate);
                boolean finishExtraction = false;
                while (!finishExtraction) {
                    ListIterator iterator = allCertificates.listIterator();
                    boolean nextCertificate = false;
                    X509Certificate certificateFromIterator = null;
                    while (iterator.hasNext() && !nextCertificate) {
                        certificateFromIterator = (X509Certificate) iterator
                                .next();
                        nextCertificate = certificateFromIterator
                                .getSubjectDN().toString().compareTo(
                                        currentCertificate.getIssuerDN()
                                                .toString()) == 0;
                    }
                    if (nextCertificate) {
                        certificateChainList.addLast(certificateFromIterator);
                        currentCertificate = certificateFromIterator;
                    }
                    finishExtraction = !nextCertificate
                            || currentCertificate.getIssuerDN().toString()
                                    .compareTo(
                                            currentCertificate.getSubjectDN()
                                                    .toString()) == 0;
                }
                certificateChain = (X509Certificate[]) certificateChainList
                        .toArray(new X509Certificate[certificateChainList
                                .size()]);

                verified = verified &&
                		signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(userCertificate));
            } else {
                throw new SignatureVerifyException(new Exception("No signer"));
            }
        } catch (Exception e) {
            log.debug("Error validating signature", e);
            throw new InternalErrorException(e.toString());
        }
        return verified;

    }

    boolean verifySignaturePKCS1(String key, String pkcs7string)
            throws InternalErrorException {
        boolean verified = true;
        try {
            byte[] pkcs1 = Base64.decode(pkcs7string);
            boolean signed = false;
            Signature s  = Signature.getInstance ("NONEwithRSA");
            if (s == null)
                throw new InternalErrorException("Invalid algorith NONEwithRSA");
            s.initVerify ( userCertificate.getPublicKey() );
            s.update ( key.getBytes("ISO-8859-1") );
            if ( s.verify (pkcs1) ) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            log.debug("Error validating signature", e);
            throw new InternalErrorException(e.toString());
        }
    }
    
    private static HashMap<String, String> certChallenges = new HashMap<String, String>();

    private String getCertChallenge(HttpServletRequest req)
            throws InternalErrorException {
        String challengeId = req.getParameter("challengeId");
        String host = certChallenges.get(challengeId);

        if (host == null)
            throw new InternalErrorException("Invalid token " + challengeId);
        if (!host.equals(req.getRemoteHost())) {
            log.warn("Ticket spoofing detected from {}", req.getRemoteHost(),
                    null);
            throw new InternalErrorException("Invalid token " + challengeId);
        }
        return challengeId;
    }

}

