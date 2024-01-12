package es.caib.seycon.idp.server;

import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.bouncycastle.util.Arrays;

public class CookieRequest extends HttpServletRequestWrapper implements ServletRequest {

	private Cookie cookie;

	public CookieRequest(HttpServletRequest req, Cookie cookie) {
		super(req);
		this.cookie = cookie;
	}

	@Override
	public Cookie[] getCookies() {
		Cookie[] c0 = super.getCookies();
		int size = c0.length;
		Cookie[] c = new Cookie[size+1];
		for (int i = 0; i < size; i++)
			c[i] = c0[i];
		c[size] = cookie;
		return c;
	}

}
