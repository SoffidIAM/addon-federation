package es.caib.seycon.idp.cert;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import es.caib.seycon.ng.exception.InternalErrorException;

/** A Jetty SSL context factory that delegates X.509 trust evaluation to the application. */
public class DelegateToApplicationSslContextFactory extends org.eclipse.jetty.http.ssl.SslContextFactory {
	static long lastRefresh = 0;
	static X509Certificate[] certs = new X509Certificate[0];
	
	public static X509Certificate[] getTrustedCerts() {
		if (lastRefresh < System.currentTimeMillis() - 5 * 60 * 1000) {
			try {
				lastRefresh = System.currentTimeMillis();
				Collection<X509Certificate> c = new RemoteServiceLocator().getCertificateValidationService().getRootCertificateList();
				certs = c.toArray(new X509Certificate[c.size()]);
			} catch (Exception e) {
				LogFactory.getLog(DelegateToApplicationSslContextFactory.class).warn("Error fetching accepted certificates", e);
			}
		}
		return certs;
	}
    /**
     * Constructor.
     * 
     * Sets {@link #setWantClientAuth(boolean)} to true and {@link #setValidateCerts(boolean)} to false.
     */
    public DelegateToApplicationSslContextFactory() {
        super();
        setWantClientAuth(true);
        setValidateCerts(false);
    }

    /** {@inheritDoc} */
    protected TrustManager[] getTrustManagers(KeyStore trustStore, Collection<? extends CRL> crls) throws Exception {
        X509TrustManager noTrustManager = new X509TrustManager() {

            /** {@inheritDoc} */
            public void checkClientTrusted(X509Certificate[] certs, String auth) {
            }

            /** {@inheritDoc} */
            public void checkServerTrusted(X509Certificate[] certs, String auth) {
            }

            /** {@inheritDoc} */
            public X509Certificate[] getAcceptedIssuers() {
                return getTrustedCerts();
            }
        };

        return new TrustManager[] {noTrustManager};
    }
}