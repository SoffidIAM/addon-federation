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

}
