package com.soffid.iam.addons.federation.idp.radius.server.web;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import com.soffid.iam.addons.federation.idp.radius.server.CertificateCache;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import es.caib.seycon.ng.exception.InternalErrorException;

/** A Jetty SSL context factory that delegates X.509 trust evaluation to the application. */
public class RadiusSslContextFactory extends org.eclipse.jetty.util.ssl.SslContextFactory.Server {
	static X509Certificate[] certs = new X509Certificate[0];
	static String dummyCertBase64 = 
			  "MIID0TCCArmgAwIBAgIUHFuDINfO5TcDFjhqWprbd6w/hfcwDQYJKoZIhvcNAQEL\n"
			+ "BQAweDELMAkGA1UEBhMCZXMxEzARBgNVBAgMClNvbWUtU3RhdGUxKTAnBgNVBAoM\n"
			+ "IGF1L0thbjRsT1RRVWdiQXMrYzlVOVp6emxuV3dOVkU1MSkwJwYDVQQDDCBhdS9L\n"
			+ "YW40bE9UUVVnYkFzK2M5VTlaenpsbld3TlZFNTAeFw0yMjA2MjMyMDM3MjNaFw0y\n"
			+ "MjA3MjMyMDM3MjNaMHgxCzAJBgNVBAYTAmVzMRMwEQYDVQQIDApTb21lLVN0YXRl\n"
			+ "MSkwJwYDVQQKDCBhdS9LYW40bE9UUVVnYkFzK2M5VTlaenpsbld3TlZFNTEpMCcG\n"
			+ "A1UEAwwgYXUvS2FuNGxPVFFVZ2JBcytjOVU5Wnp6bG5Xd05WRTUwggEiMA0GCSqG\n"
			+ "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmtGOlKy9melEvtXnIccpH+GApCk9PSotH\n"
			+ "ZQuGuUHSBgQsZcnQ2/Epx6qvEaWEr57T41knlhCgMxhOuya2t04cgjyDeePQT1Fo\n"
			+ "/5KpVmt0Shp62tMxTaoyLOgDMQerqBBgIaj7Gc6ME1NClKKSBGeQKIZTvKyiQKIV\n"
			+ "FOBYwNzomeMQceibLDfl7gRASaVYPlayKGkBAfERafRMxXn3MFWi5Hpttvt8uUAI\n"
			+ "S+YQmQqy06/fvZAfqctr+K57a2BewdN+3KcqccuOYResuMsWiPy+2bGHHG18h7D/\n"
			+ "mfVPGFTZqbOOOZ753RM7xX+R2sZb0GUgbld4yUt75u9GEZRtWxPhAgMBAAGjUzBR\n"
			+ "MB0GA1UdDgQWBBTXR+nn7tznZjfOaVd7rZO4TqrVcDAfBgNVHSMEGDAWgBTXR+nn\n"
			+ "7tznZjfOaVd7rZO4TqrVcDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n"
			+ "A4IBAQAtUbCt426vewxYQuv2bDXpWiZv794str+KJQRqrrrayCzqsIXU/WIHwHFY\n"
			+ "5cR+UGF+UcdmfVwBuSSZOqK6BwNOo3emzBg9DKfddTMDiwhZEFJigVbZHwRpCGZg\n"
			+ "+c69xhX2ULmBQX3yFMQGPaVNe/7E0YJ9EkQWBmqSzJFYh9Z8I/jNBBxGBxMgq1+u\n"
			+ "YY0fKbMB0fI1bQE5ygzqxY1k9B+LdadiCORVM1koJ4LxLaTAXwvO95g4nrBDIpOP\n"
			+ "cvRow78ezTIuNXaFM10J16Lg4fZ5evNyrp1+QZ2C6RBjQLqowXz553ngLBLISEYZ\n"
			+ "+ZKUXjhoX8E1q0bFzmeRqE1Rpijw\n";
	private static X509Certificate dummyCert = null;
	
	public X509Certificate[] getTrustedCerts() {
		final List<X509Certificate> l = certificateCache.getCertificates();
		return l.toArray(new X509Certificate[l.size()]);
	}

	private CertificateCache certificateCache;
    /**
     * Constructor.
     * 
     * Sets {@link #setWantClientAuth(boolean)} to true and {@link #setValidateCerts(boolean)} to false.
     * @param certificateCache 
     */
    public RadiusSslContextFactory(CertificateCache certificateCache) {
        super();
        this.certificateCache = certificateCache;
        setValidateCerts(false);
    }

    /** {@inheritDoc} */
    protected TrustManager[] getTrustManagers(KeyStore trustStore, Collection<? extends CRL> crls) throws Exception {
        X509TrustManager thisTrustManager = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] certs, String auth) {
            	if (certificateCache.getFederationMember(certs[0]) == null)
            		throw new RuntimeException("Certificate not accepted: "+certs[0].getSubjectDN());
            }

            /** {@inheritDoc} */
            public void checkServerTrusted(X509Certificate[] certs, String auth) {
            }

            /** {@inheritDoc} */
            public X509Certificate[] getAcceptedIssuers() {
                return getTrustedCerts();
            }
        };

        return new TrustManager[] {thisTrustManager};
    }
}