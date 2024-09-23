package es.caib.seycon.idp.ui.cred;

import java.io.IOException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.service.UserCredentialService;
import com.soffid.iam.api.User;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.idp.config.IdpConfig;

/**
 * Expects https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 * 
 * @author gbuades
 *
 */
public class ValidateRegisteredCredential extends HttpServlet {
	public static final String URI = "/validateRegisteredCredential"; //$NON-NLS-1$
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		Map<String, Object> result = new HashMap<String, Object>();
		try {
			String hash = (String) req.getSession().getAttribute("$soffid$fido_request");
			if (hash == null)
	        	throw new ServletException("Wrong URL");
	
			final UserCredentialService userCredentialService = new RemoteServiceLocator().getUserCredentialService();
			User user = userCredentialService.findUserForNewCredentialURI(hash);
	        
	        if (user == null) {
	        	throw new ServletException("Wrong URL");
	        }
	        
	
			String rawId = req.getParameter("rawId");
			String clientJSON = req.getParameter("clientJSON");
			String attestation = req.getParameter("attestation");
			HttpSession session = req.getSession();
			String challenge = (String) session.getAttribute("fingerprintChallenge");
			byte[] challengeBinary = Base64.getDecoder().decode(challenge);
					
			if (clientJSON == null || clientJSON.trim().isEmpty())
			{
				result.put("status", "error");
				result.put("cause", "Missing clientJSON attribute");
			}
			else if (attestation == null || attestation.trim().isEmpty())
			{
				result.put("status", "error");
				result.put("cause", "Missing attestation attribute");
			}
			else if (rawId == null || rawId.trim().isEmpty())
			{
				result.put("status", "error");
				result.put("cause", "Missing rawId attribute");
			}
			else 
			{
				WebCredentialParser p = new WebCredentialParser();
				p.parse(clientJSON, attestation, challengeBinary);
				UserCredential credential = new UserCredential();
				credential.setCreated(new Date());
				credential.setDescription(p.getTokenSigner());
				credential.setSerialNumber( IdpConfig.getConfig().getUserCredentialService().generateNextSerial() );
				credential.setRawid(rawId);
				credential.setType(UserCredentialType.FIDO);
				credential.setKey(p.getPublicKey());
				credential.setUserId(user.getId());
				userCredentialService.create(credential);
				userCredentialService.cancelNewCredentialURI(hash);
				result.put("status", "success");
				result.put("serial", credential.getSerialNumber());
			}
		} catch (Exception e) {
			result.put("status", "error");
			result.put("cause", e.toString());
		}
		resp.setContentType("application/json");
		ServletOutputStream out = resp.getOutputStream();
		ObjectMapper m = new ObjectMapper();
		m.writeValue(out, result);
		out.close();
	}


}
