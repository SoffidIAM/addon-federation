package com.soffid.iam.federation.idp;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.comu.lang.MessageFactory;

public class LanguageFilter implements Filter {

	private static ThreadLocal<String> currentIp = new ThreadLocal<String>();
	
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
	
		currentIp.set(req.getRemoteAddr());
		
		Locale localeToUse = request.getLocale();
		HttpSession s = req.getSession(false);
		if (s != null)
		{
			String lang = (String) s.getAttribute("lang"); //$NON-NLS-1$ //$NON-NLS-2$
			if (lang != null)
				localeToUse = new Locale (lang);
			
			LogRecorder.getInstance().keepAliveLogSession(s);
		}
		
		Locale currentLocale =  MessageFactory.getThreadLocale();
		try {
			MessageFactory.setThreadLocale(localeToUse);
			
			
			chain.doFilter(request, response);
		} finally {
			MessageFactory.setThreadLocale(currentLocale);
		}

	}

	public void destroy() {
	}
	
	public static String getRemoteIp () 
	{
		return currentIp.get();
	}

}
