package com.soffid.iam.addons.federation.api;

import java.util.Date;

import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class SseEvent {
	@Nullable @Identifier
	Long id;
	
	String receiver;
	
	@Nullable
	String subject;
	
	@Nullable
	String user;

	@Nullable
	String accountName;

	@Nullable
	String accountSystem;

	String type;

	@Description("Credentila type for credential-change event")
	@Nullable @Column(name="SEV_CRED", length = 256)
	String credentialType;
	
	@Description("Change type for credential-change event")
	@Nullable @Column(name="SEV_CHANGE", length = 256)
	String changeType;
	
	@Description("Friendly name for credential-change event")
	@Nullable @Column(name="SEV_FRINAM", length = 256)
	String friendlyName;
	
	@Description("X509 issuer for credential-change event")
	@Nullable @Column(name="SEV_509ISS", length = 256)
	String x509Issuer;
	
	@Description("X509 serial number for credential-change event")
	@Nullable @Column(name="SEV_509SER", length = 256)
	String x509Serial;
	
	@Description("Fido2 GUID for credential-change event")
	@Nullable @Column(name="SEV_AAGUID", length = 256)
	String fido2aaGuid;

	@Description("Current level for assurance-level-change event")
	@Nullable @Column(name="SEV_CURLVL", length = 256)
	String currentLevel;

	@Description("Previous level for assurance-level-change event")
	@Nullable @Column(name="SEV_PRVLVL", length = 256)
	String previousLevel;

	Date date;

}
