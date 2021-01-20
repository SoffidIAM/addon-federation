package com.soffid.iam.federation.idp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.server.SessionIdManager;
import org.eclipse.jetty.server.session.AbstractSessionIdManager;

public class PersistentSessionIdManager extends AbstractSessionIdManager {

	public boolean idInUse(String id) {
		return false;
	}

	public void addSession(HttpSession session) {
		
	}

	public void removeSession(HttpSession session) {
		
	}

	public void invalidateAll(String id) {
		
	}

	public String getClusterId(String nodeId) {
		// TODO Auto-generated method stub
		return null;
	}

	public String getNodeId(String clusterId, HttpServletRequest request) {
		// TODO Auto-generated method stub
		return null;
	}

}
