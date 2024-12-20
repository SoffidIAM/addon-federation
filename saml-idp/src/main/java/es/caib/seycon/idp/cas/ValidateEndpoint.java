package es.caib.seycon.idp.cas;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.caib.seycon.idp.openid.server.TokenHandler;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;

public class ValidateEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());

	private static String RESPONSE_NO = "No";
	private static String RESPONSE_YES = "Yes";

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String ticket = req.getParameter("ticket");
		String service = req.getParameter("service");
		resp.setContentType("text/plain");
		resp.setCharacterEncoding("utf-8");
		final ServletOutputStream out = resp.getOutputStream();
		if (service == null) {
			out.println(RESPONSE_NO );
			resp.setStatus(HttpServletResponse.SC_OK);
		} else {
			try {
				TokenHandler h = TokenHandler.instance();
				TokenInfo t = null;
				t = h.getToken(ticket);
				if (t == null ||  
						! service.equals(t.getRequest().getFederationMember().getPublicId())) {
					out.println(RESPONSE_NO );
					resp.setStatus(HttpServletResponse.SC_OK);
				} else {
					out.println(RESPONSE_YES );
					
					Map<String, Object> atts = new UserAttributesGenerator().generateAttributes(req.getServletContext(), t, false, false, true);
					
					out.println((String)atts.get("uid"));
					
					resp.setStatus(HttpServletResponse.SC_OK);
				}
			} catch (Exception e) {
				log.warn("Error checking for CAS ticket", e);
				out.println(RESPONSE_NO );
				resp.setStatus(HttpServletResponse.SC_OK);
			}
		}
	}
}
