package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.StringReader;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedList;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import com.soffid.iam.addons.federation.common.IdpNetworkConfig;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class CertificateValidator {
	org.apache.commons.logging.Log log = LogFactory.getLog(getClass());
	
    public String validate(HttpServletRequest req) throws InternalErrorException, IOException, UnknownUserException {
        X509Certificate[] certs = getCerts(req);
        if (certs == null) {
        	log.info("No cert found");
        	return null;
        }
        return validate (certs);

    }

	public X509Certificate[] getCerts(HttpServletRequest req) throws InternalErrorException {
		X509Certificate certs[] = (X509Certificate[]) req
                .getAttribute("javax.servlet.request.X509Certificate"); //$NON-NLS-1$
        if (certs == null) {
        	String header;
			try {
				for (IdpNetworkConfig nc: IdpConfig.getConfig().getFederationMember().getNetworkConfig()) {
					if (nc.isProxy() && 
							req.getLocalPort() == nc.getProxyPort() &&
							nc.isWantsCertificate() && 
							nc.getCertificateHeader() != null &&
							!nc.getCertificateHeader().trim().isEmpty()) 
					{
						header = nc.getCertificateHeader();
						if (header != null && !header.trim().isEmpty()) {
							String cert = req.getHeader(header);
							if (cert != null && ! cert.trim().isEmpty()) {
								certs = parseCerts(cert);
							}
						}
						
					}
				}
			} catch (UnrecoverableKeyException | InvalidKeyException | KeyStoreException | NoSuchAlgorithmException
					| CertificateException | IllegalStateException | NoSuchProviderException | SignatureException
					| IOException e) {
				throw new InternalErrorException ("Error getting configuration", e);
			}
        }
		return certs;
	}

	protected X509Certificate[] parseCerts(String pemCerts) throws IOException, CertificateException {
		Object object;
		JcaX509CertificateConverter converter2 = new JcaX509CertificateConverter().setProvider( "BC" );
		LinkedList<Certificate> certs = new LinkedList<Certificate>();
		if (pemCerts.contains("%"))
			pemCerts = URLDecoder.decode(pemCerts, "UTF-8");
		pemCerts = pemCerts.replace(" ", "\n").replace("---BEGIN\n", "---BEGIN ").replace("---END\n", "---END ");
		PEMParser pemParser = new PEMParser(new StringReader(pemCerts));
		do {
			object = pemParser.readObject();
			if (object == null) break;
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

	public Host validateHost(X509Certificate certs[], String hostId) throws InternalErrorException, IOException, UnknownUserException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
        if (certs == null || certs.length == 0) {
            return null;
        } else {
        	return IdpConfig.getConfig().getFederationService()
        		.getCertificateHost(Arrays.asList(certs), hostId);
        }

    }
}
