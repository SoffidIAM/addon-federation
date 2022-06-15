package es.caib.seycon.idp.cert;

import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.eclipse.jetty.server.ssl.SslSelectChannelConnector;

/** A Jetty SSL connector that delegates X.509 trust evaluation to the application. */
public class DelegateToApplicationSslSelectChannelConnector extends SslSelectChannelConnector {

    /** Trustmanager used by this connector. */
    private TrustManager[] trustManagers;

    /** Constructor. */
    public DelegateToApplicationSslSelectChannelConnector() {
        super();

        X509TrustManager noTrustManager = new X509TrustManager() {

            /** {@inheritDoc} */
            public void checkClientTrusted(X509Certificate[] certs, String auth) {
            }

            /** {@inheritDoc} */
            public void checkServerTrusted(X509Certificate[] certs, String auth) {
            }

            /** {@inheritDoc} */
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[] {};
            }
        };

        trustManagers = new TrustManager[] {noTrustManager};
    }

    /** {@inheritDoc} */
    public boolean isAllowRenegotiate() {
        return false;
    }

    /**
     * {@inheritDoc}
     * 
     * This method always returns "TLS".
     */
    public String getProtocol() {
        return "TLS";
    }

    /**
     * {@inheritDoc}
     * 
     * This method always returns true.
     */
    public boolean getWantClientAuth() {
        return true;
    }

    /**
     * {@inheritDoc}
     * 
     * This method already returns a single {@link X509TrustManager} that accepts any certificate given to it.
     */
    protected TrustManager[] getTrustManagers() throws Exception {
        return trustManagers;
    }
}