package com.soffid.iad.addons.federation.idp.tacacs;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.servlet.ServletContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.idp.radius.server.NetmaskMatch;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.ssl.SeyconKeyStore;

import es.caib.seycon.ng.exception.InternalErrorException;

public class TacacsServerListener extends Thread {
	boolean ssl;
	private Integer authPort = 49;
	Log log = LogFactory.getLog(getClass());
	private ServletContext servletContext;
	
	@Override
	public void run() {
		log.info("Starting TACACS+ server in port "+authPort);
		ServerSocket ss;
		SSLServerSocketFactory sslFactory = null;
		try {
			if (ssl) {
				SSLContext sslCtx = SSLContext.getInstance("TLS"); //$NON-NLS-1$
				
				KeyStore keyStore = SeyconKeyStore.loadKeyStore(SeyconKeyStore.getKeyStoreFile());
				List<String> keys = new LinkedList<String>();
				for (Enumeration<String> e = keyStore.aliases(); e.hasMoreElements();)
				{
					String alias = e.nextElement();
					if ( keyStore.isKeyEntry(alias) && ! alias.equalsIgnoreCase("idp"))
						keys.add(alias);
					if ( keyStore.isCertificateEntry(alias) && ! alias.equalsIgnoreCase(SeyconKeyStore.ROOT_CERT))
						keys.add(alias);
				}
				for (String key: keys)
					keyStore.deleteEntry(key);
				KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");        
				keyManagerFactory.init(keyStore, SeyconKeyStore.getKeyStorePassword().getPassword().toCharArray());
				KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
				
				sslCtx.init(new KeyManager[] { new TacacsKeyManager()}, 
						new TrustManager[0], null);
				
				sslFactory = sslCtx.getServerSocketFactory();
				ss = sslFactory.createServerSocket(authPort);
			} else {
				 ss = new ServerSocket(authPort);
			}
		} catch (Exception e) {
			log.fatal("Error initializing server conection", e);
			return;
		}
		while (true)
		{
			try {
				Socket s = ss.accept();
				FederationMember sp = getServiceProvider((InetSocketAddress) s.getRemoteSocketAddress());
				if (sp == null) {
					log.warn("Cannot find a valid service provider entry for IP address "+s.getRemoteSocketAddress().toString());
					s.close();
				} else {
					TacacsServer ts = new TacacsServer(s, sp.getRadiusSecret().getPassword(), sp);
					ts.start();
				}
			} catch (Exception e) {
				log.warn("Error listening to server socket", e);
			}
		}
	}

	public FederationMember getServiceProvider(InetSocketAddress client) throws InternalErrorException, IOException {
		final Collection<FederationMember> servers = new RemoteServiceLocator().getFederacioService().findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "S");
		for (FederationMember sp: servers) {
			if (sp.getServiceProviderType() == ServiceProviderType.TACACSP) {
				if (NetmaskMatch.matches(sp.getSourceIps(), client.getAddress())) {
					return sp;
				}
			}
		}
		return null;
	}

	public void setAuthPort(Integer authPort) {
		this.authPort = authPort;
	}

	public void setServletContext(ServletContext ctx) {
		this.servletContext = ctx;
	}

	public void setSsl(boolean ssl) {
		this.ssl = ssl;
	}
}
