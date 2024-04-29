package es.caib.seycon.idp.sse.server;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String method = req.getMethod();
        if ("PATCH".equalsIgnoreCase(method))
        	this.doPatch(req, resp);
        else
            super.service(req, resp);
    }

    protected void doPatch(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    }
}
