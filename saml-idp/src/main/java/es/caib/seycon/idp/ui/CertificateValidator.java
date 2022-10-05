package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class CertificateValidator {
	org.apache.commons.logging.Log log = LogFactory.getLog(getClass());
	
    public String validate(HttpServletRequest req) throws InternalErrorException, IOException, UnknownUserException {
        X509Certificate certs[] = (X509Certificate[]) req
                .getAttribute("javax.servlet.request.X509Certificate"); //$NON-NLS-1$
        if (certs == null) {
        	String header;
			try {
				header = IdpConfig.getConfig().getFederationMember().getSslClientCertificateHeader();
				if (header != null && !header.trim().isEmpty()) {
					String cert = req.getHeader(header);
					if (cert != null && ! cert.trim().isEmpty()) {
						certs = parseCerts(cert);
					}
				}
			} catch (UnrecoverableKeyException | InvalidKeyException | KeyStoreException | NoSuchAlgorithmException
					| CertificateException | IllegalStateException | NoSuchProviderException | SignatureException
					| IOException e) {
				throw new InternalErrorException ("Error getting configuration", e);
			}
        }
        if (certs == null) {
        	log.info("No cert found");
        	return null;
        }
        return validate (certs);

    }

	protected X509Certificate[] parseCerts(String pemCerts) throws IOException, CertificateException {
		Object object;
		JcaX509CertificateConverter converter2 = new JcaX509CertificateConverter().setProvider( "BC" );
		LinkedList<Certificate> certs = new LinkedList<Certificate>();
		pemCerts = pemCerts.replace(" ", "\n").replace("---BEGIN\n", "---BEGIN ").replace("---END\n", "---END ");
		PEMParser pemParser = new PEMParser(new StringReader(pemCerts));
		do {
			object = pemParser.readObject();
			if (object == null) break;
			System.out.println(">>> object  ="+object);
			System.out.println(">>> instance of ="+object.getClass());
			if (object instanceof X509CertificateHolder)
			{
				certs.add(converter2.getCertificate((X509CertificateHolder) object));
			}
		} while (true);
		return certs.toArray(new X509Certificate[certs.size()]);
	}

	public String validate(X509Certificate certs[]) throws InternalErrorException, IOException, UnknownUserException {
        if (certs == null || certs.length == 0) {
            return null;
        } else {
        	com.soffid.iam.sync.service.ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
            User ui = server.getUserInfo(certs);
            if (ui == null)
            	return null;

            IdpConfig cfg;
    		try {
    			cfg = IdpConfig.getConfig();
    		} catch (Exception e) {
    			throw new InternalErrorException("Error getting default dispatcher", e);
    		}
    		for (UserAccount account: server.getUserAccounts(ui.getId(), cfg.getSystem().getName())) {
    			if (!account.isDisabled()) {
    				return account.getName();
    			}
    			else
    				LogFactory.getLog(getClass()).warn("User "+ui.getUserName()+" cannot login because account "+account.getName()+" is not enabled");
    		}
    		return null;
        }

    }
}
