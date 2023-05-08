package com.soffid.iam.addons.federation.idp.radius.server;

import java.io.StringReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.jfree.util.Log;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import es.caib.seycon.idp.config.IdpConfig;

public class TrustRadiusServers implements X509TrustManager {
	long lastChange = 0;
	List<X509Certificate> list = new LinkedList<>();
	private CertificateCache certificateCache;
	public TrustRadiusServers(CertificateCache certificateCache) {
		this.certificateCache = certificateCache;
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		if ( ! certificateCache.getCertificates().contains(chain[0]))
			throw new CertificateException("Unknown certificate "+chain[0].getSubjectDN());
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		if ( ! certificateCache.getCertificates().contains(chain[0]))
			throw new CertificateException("Unknown certificate "+chain[0].getSubjectDN());
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		List<X509Certificate> certs = certificateCache.getCertificates();
		return certs.toArray(new X509Certificate[certs.size()]);
	}
}
