package es.caib.seycon.idp.ui.cred;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
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

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.UserCredentialType;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;

public class RegisterCredential extends HttpServlet {
	public static final String URI = "/registerCredential"; //$NON-NLS-1$
	static final Counter counter =  new Counter();
	
	@Override
	/**
	 * {"type":"webauthn.create","challenge":"vIGpg60Ar7Auae37DzjC57ZqpKvyUJ99n7lSFbrNQm6AS2m4V-mVT_tOUSCFzZUD7JC3G2cdA8-lxCq885yE5A","origin":"https:\/\/soffid.bubu.lab:2443","androidPackageName":"com.android.chrome"}
	 * 
	 * {fmt=android-safetynet, attStmt={ver=19831037, response=[B@64d1d7a}, authData=[B@3a954724}
	 */
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String rawId = req.getParameter("rawId");
		String clientJSON = req.getParameter("clientJSON");
		String attestation = req.getParameter("attestation");
		HttpSession session = req.getSession();
		String challenge = (String) session.getAttribute("fingerprintChallenge");
		byte[] challengeBinary = Base64.getDecoder().decode(challenge);
				
		Map<String, Object> result = new HashMap<String, Object>();
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
			try {
				p.parse(clientJSON, attestation, challengeBinary);
				UserCredential credential = new UserCredential();
				credential.setCreated(new Date());
				credential.setDescription(p.getTokenSigner());
				credential.setSerialNumber( IdpConfig.getConfig().getUserCredentialService().generateNextSerial() );
				credential.setRawid(rawId);
				credential.setType(UserCredentialType.FIDO);
				credential.setKey(p.getPublicKey());
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        		ctx.setNewCredential(credential);
				result.put("status", "success");
				result.put("serial", credential.getSerialNumber());
			} catch (Exception e) {
				result.put("status", "error");
				result.put("cause", e.toString());
			}
		}
		resp.setContentType("application/json");
		ServletOutputStream out = resp.getOutputStream();
		ObjectMapper m = new ObjectMapper();
		m.writeValue(out, result);
		out.close();
	}

	private int intValue(byte[] authData, int i) {
		int r = (int) authData[i];
		if (r < 0 ) r += 256;
		return r;
	}

}

class Counter {
	long next = System.currentTimeMillis();
} 
