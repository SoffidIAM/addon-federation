package es.caib.seycon.idp.https;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import com.soffid.iam.ssl.ConnectionFactory;

public class ApacheSslSocketFactory implements ProtocolSocketFactory {
    public static void register () {
        ApacheSslSocketFactory sf = new ApacheSslSocketFactory();

        Protocol p = Protocol.getProtocol("https"); //$NON-NLS-1$
        if (p != null) Protocol.unregisterProtocol("https"); //$NON-NLS-1$
        
        Protocol.registerProtocol("https", new Protocol ("https", sf, 443)); //$NON-NLS-1$ //$NON-NLS-2$

    }

    public Socket createSocket(String host, int port, InetAddress localAddress,
            int localPort) throws IOException, UnknownHostException {
        SSLSocketFactory factory;
        try {
            factory = ConnectionFactory.getSocketFactory();
        } catch (Exception e) {
            throw new IOException(e);
        }
        return factory.createSocket(host, port, localAddress, localPort);
    }

    public Socket createSocket(String host, int port, InetAddress localAddress,
            int localPort, HttpConnectionParams params) throws IOException,
            UnknownHostException, ConnectTimeoutException {
        SSLSocketFactory factory;
        try {
            factory = ConnectionFactory.getSocketFactory();
        } catch (Exception e) {
            throw new IOException(e);
        }
        return factory.createSocket(host, port, localAddress, localPort);
    }

    public Socket createSocket(String host, int port) throws IOException,
            UnknownHostException {
        SSLSocketFactory factory;
        try {
            factory = ConnectionFactory.getSocketFactory();
        } catch (Exception e) {
            throw new IOException(e);
        }
        return factory.createSocket(host, port);
    }


}
