package es.caib.seycon.idp.openid.server;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

public class OidcDebugController {
	static long lastCheck = 0;
	static boolean debug = false;

	public static boolean isDebug() {
		if (lastCheck + 60000 < System.currentTimeMillis()) {
			try {
				debug = "true".equals(new RemoteServiceLocator().getServerService().getConfig("soffid.idp.oidc.trace"));
				lastCheck = System.currentTimeMillis();
			} catch (Exception e) {
			}
		}
			
		return debug;
	}

	public static String ofuscate(String s) {
		if (s == null) 
			return "";
		else if (s.length() < 4)
			return "****";
		else
			return s.substring(0,4)+"****";
	}

}
