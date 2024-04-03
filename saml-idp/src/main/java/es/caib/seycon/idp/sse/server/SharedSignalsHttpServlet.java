package es.caib.seycon.idp.sse.server;

import javax.servlet.http.HttpServlet;

public class SharedSignalsHttpServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	protected String getFramework() {
		return super.getServletName().substring(0,3);
	}

	protected boolean isSSE() {
		return Events.SSE.equals(getFramework());
	}

	protected boolean isSSF() {
		return Events.SSF.equals(getFramework());
	}
}
