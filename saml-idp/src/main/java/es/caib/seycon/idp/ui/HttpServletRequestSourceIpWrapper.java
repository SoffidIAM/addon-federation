package es.caib.seycon.idp.ui;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;


public class HttpServletRequestSourceIpWrapper extends HttpServletRequestWrapper {

	private String address;

	public HttpServletRequestSourceIpWrapper(HttpServletRequest request, String sourceAddress) {
		super(request);
		this.address = sourceAddress;
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

}
