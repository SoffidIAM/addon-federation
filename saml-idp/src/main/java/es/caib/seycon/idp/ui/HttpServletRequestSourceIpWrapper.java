package es.caib.seycon.idp.ui;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.logging.LogFactory;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;


public class HttpServletRequestSourceIpWrapper extends HttpServletRequestWrapper {

	private String address;
	private HashMap<String,List<String>> headers;

	public HttpServletRequestSourceIpWrapper(HttpServletRequest request, String sourceAddress) {
		super(request);
		this.address = sourceAddress;
		headers = new HashMap<>();
		for (Enumeration<String> e = request.getHeaderNames(); e.hasMoreElements(); ) {
			String name = e.nextElement();
			List<String> values = new LinkedList<>();
			headers.put(name, values);
			for (Enumeration<String> ee = request.getHeaders(name); ee.hasMoreElements();) {
				values.add(ee.nextElement());
			}
		}
		String clientCertHeader;
		try {
			clientCertHeader = IdpConfig.getConfig().getFederationMember().getSslClientCertificateHeader();
		} catch (Exception e) {
			throw new RuntimeException("Error getting client cert header name", e);
		}
		if (sourceAddress.equals(request.getRemoteAddr()) && clientCertHeader != null) {
			headers.remove(clientCertHeader);
		}
	}

	@Override
	public String getRemoteAddr() {
		return address;
	}

	@Override
	public String getRemoteHost() {
		return address;
	}

	@Override
	public String getScheme() {
		return "https"; // For servers behind a reverse proxy
	}

	@Override
	public String getRequestURI() {
		String s = super.getRequestURI();
		if (s.startsWith("http:"))
			s = "https:"+s.substring(5);
		return s;
	}

	@Override
	public StringBuffer getRequestURL() {
		StringBuffer s = super.getRequestURL();
		if (s.toString().startsWith("http:"))
			s = new StringBuffer( "https:"+s.toString().substring(5));
		return s;
	}

	@Override
	public String getHeader(String name) {
		List<String> l = headers.get(name);
		if (l == null || l.isEmpty())
			return null;
		else
			return l.iterator().next();
	}

	@Override
	public Enumeration<String> getHeaders(String name) {
		List<String> l = headers.get(name);
		if (l == null) Collections.emptyEnumeration();
		return Collections.enumeration(l);
	}

	@Override
	public Enumeration<String> getHeaderNames() {
		return Collections.enumeration(headers.keySet());
	}

}
