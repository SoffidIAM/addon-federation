package com.soffid.iam.addons.federation.model;

import java.util.Date;

import com.soffid.iam.addons.federation.api.SseSubscription;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_SSESUB")
@Depends({SseSubscription.class})
public class SseSubscriptionEntity {
	@Identifier @Column(name="SSS_ID")
	Long id;
	
	@Column(name="SSS_REC_ID", reverseAttribute = "subjects")
	SseReceiverEntity receiver;
	
	@Nullable
	@Column(name="SSS_USER", length = 256)
	String userName;
	
	@Nullable
	@Column(name="SSS_ACCNAM", length = 256)
	String accountName;

	@Nullable
	@Column(name="SSS_SYSTEM", length = 256)
	String system;

	@Column(name="SSS_TYPE", length = 256)
	String type;

	@Column(name="SSS_DATE")
	Date date;
}

