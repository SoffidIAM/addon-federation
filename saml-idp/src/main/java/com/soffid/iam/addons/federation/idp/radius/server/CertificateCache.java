package com.soffid.iam.addons.federation.idp.radius.server;

import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.jfree.util.Log;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

public class CertificateCache {
	Map <X509Certificate, String> certs;
	Map <String, FederationMember> members;
	
	long lastChange = 0;
	public synchronized void refresh() {
		if (lastChange + 60000 < System.currentTimeMillis()) {
			try {
				certs = new HashMap<>();
				members = new HashMap<>();
				final Collection<FederationMember> servers = new RemoteServiceLocator().getFederacioService().findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "S");
				for (FederationMember sp: servers) {
					if (sp.getServiceProviderType() == ServiceProviderType.RADIUS &&
							sp.getServerCertificate() != null) {
						for (X509Certificate cert: parseCertificate(sp.getPublicId(), sp.getServerCertificate())) {
							certs.put(cert, sp.getPublicId());
							members.put(sp.getPublicId(), sp);
						}
					}
				}
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		lastChange = System.currentTimeMillis();
	}

	private LinkedList<X509Certificate> parseCertificate(String sp, String serverCertificate) {
		LinkedList<X509Certificate> certs = new LinkedList<X509Certificate>();
		try {
			Object object;
			JcaX509CertificateConverter converter2 = new JcaX509CertificateConverter().setProvider( "BC" );
			PEMParser pemParser = new PEMParser(new StringReader(
	                serverCertificate));
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
		} catch (Exception e) {
			Log.warn("Error parsing certificate for "+sp);
		}
		return certs;
	}
	
	public List<X509Certificate> getCertificates() {
		refresh();
		return new LinkedList<>(certs.keySet());
	}
	
	public FederationMember getFederationMember (X509Certificate cert) {
		refresh();
		String publicId = certs.get(cert);
		if (publicId == null)
			return null;
		else
			return members.get(publicId);
	}
	
	
}
