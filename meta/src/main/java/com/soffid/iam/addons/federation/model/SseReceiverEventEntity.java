package com.soffid.iam.addons.federation.model;

import java.util.Date;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_SSEREV")
public class SseReceiverEventEntity {
	@Nullable @Identifier @Column(name = "SSE_ID")
	Long id;
	
	@Column(name="SSE_NAME", length = 100)
	String name;
	
	@Column(name="SSE_SSR_ID", reverseAttribute = "events")
	SseReceiverEntity receiver;
}
