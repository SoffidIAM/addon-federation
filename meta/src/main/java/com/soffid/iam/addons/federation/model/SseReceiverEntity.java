package com.soffid.iam.addons.federation.model;

import java.util.Date;

import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SseReceiverMethod;
import com.soffid.iam.addons.federation.api.SubjectFormatEnumeration;
import com.soffid.iam.addons.federation.api.SubjectSourceEnumeration;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

import es.caib.seycon.ng.model.DispatcherEntity;

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
	
	@Nullable @Column(name="SSR_SUBTYP")
	SubjectFormatEnumeration subjectType;
	
	@Nullable @Column(name="SSR_SSLKEY", length = 4096)
	String sslKey;
	
	@Nullable @Column(name="SSR_SSLPUB", length = 4096)
	String sslPublicKey;

	@Nullable @Column(name="SSR_SSLCER", length = 64000)
	String sslCertificate;
	
	@Nullable @Column(name="SSR_QUESIZ")
	Integer queueSize;
	
	@Nullable @Column(name="SSR_SRCTYP", length = 64)
	SubjectSourceEnumeration sourceType;
	
	@Nullable @Column(name="SSR_SRCEXP", length = 64000)
	String sourceExpression;
	
	@Nullable @Column(name="SSR_SRCOAU", length = 128)
	String sourceOAuth;
	
	@Nullable @Column(name="SSR_SRC_DIS_ID")
	DispatcherEntity system;

	@Column(name="SSR_TEN_ID")
	TenantEntity tenant;
}
