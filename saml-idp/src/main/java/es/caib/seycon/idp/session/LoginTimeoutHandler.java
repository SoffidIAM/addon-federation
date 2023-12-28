package es.caib.seycon.idp.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class LoginTimeoutHandler {
	public static long DURATION = 9L * 60L * 1000L / 2L ; // 4 Minutes 30 seconds
	public void registerSession (HttpServletRequest req) {
		HttpSession s = req.getSession();
		Long l = new Long (System.currentTimeMillis() + DURATION);
		s.setAttribute("$$soffid-ui-timeout$$", l);
	}

	public long getTimeToTimeout (HttpServletRequest req) {
		HttpSession s = req.getSession(false);
		if (s == null) return DURATION;
				
		Long l = (Long) s.getAttribute("$$soffid-ui-timeout$$");
		final long currentTimeMillis = System.currentTimeMillis();

		if (l == null) return DURATION;
		else if (l.longValue() < currentTimeMillis) return 0;
		else return l.longValue() - currentTimeMillis;
	}
	
	public boolean isTimedOut (HttpServletRequest req) {
		return getTimeToTimeout(req) < 1000;
	}

}
