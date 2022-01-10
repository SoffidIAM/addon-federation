package es.caib.seycon.idp.session;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Session;

import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;

public class SessionListener implements HttpSessionListener {

	static Map<String, Session> sessionMap = new Hashtable<String, Session>();
	static Set<String> sessions = new HashSet<String>();
	public static void registerSession (HttpSession session, Session sessio)
	{
		sessionMap.put(session.getId(), sessio);
		sessions.add(sessio.getId().toString());
	}
	
	public static boolean isSessionAlive (String soffidSessionId)
	{
		return sessions.contains(soffidSessionId);
	}
	
	public void sessionCreated(HttpSessionEvent se) {
	}
	
	public void sessionDestroyed(HttpSessionEvent se) {
		LogRecorder.getInstance().closeSession(se.getSession());
		Session soffidSession = sessionMap.get(se.getSession().getId());
		if (soffidSession != null)
		{
			sessionMap.remove(se.getSession().getId());
			sessions.remove(soffidSession.getId().toString());
			try {
				new RemoteServiceLocator().getSessionService().destroySession(soffidSession);
			} catch (Exception e) {
				LogFactory.getLog(getClass()).warn("Error closing session", e);
			}
		}
		
	}

}
