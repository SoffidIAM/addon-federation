//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Federation Service.
 * 
 * Common services for user authentication:
 * 
 * - generateSamlRequest: generates a SAML request 
 * - authenticate: parses and validates a SAML request, generating a sessino cookie
 * - checkSessionCookie: parses and validates a SAML session cookie
 * 
 */
import org.springframework.transaction.annotation.Transactional;

import com.soffid.iam.addons.federation.api.DocumentVerification;
import com.soffid.iam.addons.federation.api.FacialVerification;
import com.soffid.iam.addons.federation.api.LivenessVerification;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.Service;


@Service ( serverPath="/seycon/IdentityVerificationService",
	 serverRole="agent")
@Depends ({
	FederationMemberEntity.class
})
public abstract class IdentityVerificationService {
	public byte[] generatePngQr(String url) {return null;}
	
	public String startDocumentVerification(
			String identityProvider,
			@Nullable String country, @Nullable String type,
			String mimeType,
			byte [] front,
			@Nullable byte[] back) {
		return null;
	}

	public DocumentVerification getDocumentVerification(String identityProvider, String verificationId) {
		return null;
	}
	
	public FacialVerification authenticateFacial(String identityProvider, String image1, String image2) 
	{ return null; }

	public LivenessVerification passiveLiveness(String identityProvider, String image1) 
	{ return null; }

}
