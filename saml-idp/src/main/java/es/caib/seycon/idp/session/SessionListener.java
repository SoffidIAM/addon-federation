package es.caib.seycon.idp.session;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import edu.internet2.middleware.shibboleth.idp.session.Session;
import es.caib.seycon.idp.shibext.LogRecorder;

public class SessionListener implements HttpSessionListener {

	static Map<String, String> sessionMap = new HashMap<String, String>();
	static Set<String> sessions = new HashSet<String>();
	
	public static void registerSession (HttpSession session, String sofidSessionId)
	{
		sessionMap.put(session.getId(), sofidSessionId);
		sessions.add(sofidSessionId);
	}
	
	public static boolean isSessionAlive (String soffidSessionId)
	{
		return sessions.contains(soffidSessionId);
	}
	
	public void sessionCreated(HttpSessionEvent se) {
	}

	public void sessionDestroyed(HttpSessionEvent se) {
		LogRecorder.getInstance().closeSession(se.getSession());
		String soffidSessionId = sessionMap.get(se.getSession().getId());
		if (soffidSessionId != null)
		{
			sessionMap.remove(se.getSession().getId());
			sessions.remove(soffidSessionId);
		}
		
	}

}
