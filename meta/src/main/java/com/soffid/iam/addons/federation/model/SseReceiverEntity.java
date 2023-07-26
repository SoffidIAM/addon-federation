package com.soffid.iam.addons.federation.model;

import java.util.Date;

import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SseReceiverMethod;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_SSEREC")
@Depends({SseReceiver.class})
public class SseReceiverEntity {
	@Nullable @Identifier @Column(name = "SSR_ID")
	Long id;
	
	@Column(name="SSR_NAME", length = 100)
	String name;
	
	@Column(name="SSR_DESCRI", length = 512)
	String description;
	
	@Nullable @Column(name="SSR_TOKEN")
	String token;

	@Nullable @Column(name="SSR_EXPIRE")
	Date expiration;

	@Nullable @Column(name="SSR_SRCIP")
	String sourceIps;
	
	@Nullable @Column(name="SSR_METHOD")
	SseReceiverMethod method;
	
	@Nullable @Column(name="SSR_URL", length = 256)
	String url;
	
	@Column(name="SSR_TEN_ID")
	TenantEntity tenant;
}
