package es.caib.seycon.idp.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
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
	static String dummyCertBase64 = 
			  "MIID0TCCArmgAwIBAgIUHFuDINfO5TcDFjhqWprbd6w/hfcwDQYJKoZIhvcNAQEL"
			+ "BQAweDELMAkGA1UEBhMCZXMxEzARBgNVBAgMClNvbWUtU3RhdGUxKTAnBgNVBAoM"
			+ "IGF1L0thbjRsT1RRVWdiQXMrYzlVOVp6emxuV3dOVkU1MSkwJwYDVQQDDCBhdS9L"
			+ "YW40bE9UUVVnYkFzK2M5VTlaenpsbld3TlZFNTAeFw0yMjA2MjMyMDM3MjNaFw0y"
			+ "MjA3MjMyMDM3MjNaMHgxCzAJBgNVBAYTAmVzMRMwEQYDVQQIDApTb21lLVN0YXRl"
			+ "MSkwJwYDVQQKDCBhdS9LYW40bE9UUVVnYkFzK2M5VTlaenpsbld3TlZFNTEpMCcG"
			+ "A1UEAwwgYXUvS2FuNGxPVFFVZ2JBcytjOVU5Wnp6bG5Xd05WRTUwggEiMA0GCSqG"
			+ "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmtGOlKy9melEvtXnIccpH+GApCk9PSotH"
			+ "ZQuGuUHSBgQsZcnQ2/Epx6qvEaWEr57T41knlhCgMxhOuya2t04cgjyDeePQT1Fo"
			+ "/5KpVmt0Shp62tMxTaoyLOgDMQerqBBgIaj7Gc6ME1NClKKSBGeQKIZTvKyiQKIV"
			+ "FOBYwNzomeMQceibLDfl7gRASaVYPlayKGkBAfERafRMxXn3MFWi5Hpttvt8uUAI"
			+ "S+YQmQqy06/fvZAfqctr+K57a2BewdN+3KcqccuOYResuMsWiPy+2bGHHG18h7D/"
			+ "mfVPGFTZqbOOOZ753RM7xX+R2sZb0GUgbld4yUt75u9GEZRtWxPhAgMBAAGjUzBR"
			+ "MB0GA1UdDgQWBBTXR+nn7tznZjfOaVd7rZO4TqrVcDAfBgNVHSMEGDAWgBTXR+nn"
			+ "7tznZjfOaVd7rZO4TqrVcDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA"
			+ "A4IBAQAtUbCt426vewxYQuv2bDXpWiZv794str+KJQRqrrrayCzqsIXU/WIHwHFY"
			+ "5cR+UGF+UcdmfVwBuSSZOqK6BwNOo3emzBg9DKfddTMDiwhZEFJigVbZHwRpCGZg"
			+ "+c69xhX2ULmBQX3yFMQGPaVNe/7E0YJ9EkQWBmqSzJFYh9Z8I/jNBBxGBxMgq1+u"
			+ "YY0fKbMB0fI1bQE5ygzqxY1k9B+LdadiCORVM1koJ4LxLaTAXwvO95g4nrBDIpOP"
			+ "cvRow78ezTIuNXaFM10J16Lg4fZ5evNyrp1+QZ2C6RBjQLqowXz553ngLBLISEYZ"
			+ "+ZKUXjhoX8E1q0bFzmeRqE1Rpijw";
	private static X509Certificate dummyCert = null;
	
	public static X509Certificate[] getTrustedCerts() {
		if (lastRefresh < System.currentTimeMillis() - 5 * 60 * 1000) {
			try {
				lastRefresh = System.currentTimeMillis();
				Collection<X509Certificate> c = new RemoteServiceLocator().getCertificateValidationService().getRootCertificateList();
				if (c.isEmpty()) {
					if (dummyCert == null) {
						byte[] data = Base64.getDecoder().decode(dummyCertBase64);
						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
						dummyCert = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(data));
					}
					c.add(dummyCert);
				}
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