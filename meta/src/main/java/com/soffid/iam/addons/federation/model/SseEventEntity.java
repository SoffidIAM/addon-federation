package com.soffid.iam.addons.federation.model;

import java.util.Date;
import java.util.List;

import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.DaoFinder;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_SSEEVT")
@Depends({SseEvent.class})
public class SseEventEntity {
	@Nullable @Identifier
	@Column(name="SEV_ID")
	Long id;
	
	@Column(name="SEV_REC_ID", reverseAttribute = "events")
	SseReceiverEntity receiver;

	@Nullable
	@Column(name="SEV_SUBJEC", length = 256)
	String subject;
	
	@Nullable
	@Column(name="SEV_USER", length = 256)
	String user;

	@Nullable
	@Column(name="SEV_ACCNAM", length = 256)
	String accountName;

	@Nullable
	@Column(name="SEV_ACCSYS", length = 256)
	String accountSystem;

	@Column(name="SEV_TYPE", length = 256)
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

	@Column(name="SSS_DATE")
	Date date;
	
	@DaoFinder("select e "
			+ "from com.soffid.iam.addons.federation.model.SseEventEntity as e "
			+ "where e.receiver.name = :receiver "
			+ "order by e.id asc")
	List<SseEventEntity> findByReceiver(String receiver) { return null; }

	@DaoFinder("select count(*) "
			+ "from com.soffid.iam.addons.federation.model.SseEventEntity as e "
			+ "where e.receiver.name = :receiver "
			+ "order by e.id asc")
	Long countByReceiver(String receiver) { return null; }
	

}
