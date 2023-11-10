package com.soffid.iam.addons.federation.api;

import java.util.Date;
import java.util.List;

import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Attribute;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.JsonAttribute;
import com.soffid.mda.annotation.JsonObject;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

import es.caib.seycon.ng.model.DispatcherEntity;

@ValueObject @JsonObject(hibernateClass = SseReceiverEntity.class)
public class SseReceiver {
	@Nullable @Attribute(hidden=true)
	Long id;
	
	@Description("Receiver name")
	String name;
	
	@Description("Receiver notes")
	String description;
	
	@Nullable
	@Description("Security token")
	Digest token;

	@Nullable
	@Description("Bearer token to use")
	Date expiration;

	@Nullable
	@Description("Allowed source IPs")
	String sourceIps;

	@Nullable
	@Attribute(readonly = true)
	@Description("Subscription mechanism")
	SseReceiverMethod method;
	
	@Nullable @Attribute(readonly = true)
	@Description("Subscription URL")
	String url;
	
	@Nullable @Attribute(defaultValue = "new java.util.LinkedList()", readonly = true, type = "STRING", multivalue = true)
	@JsonAttribute(hibernateJoin = "events as events", hibernateAttribute = "events.name")
	@Description("Subscribed events")
	List<String> events;
	
	@Nullable @Column(name="SSR_SUBTYP")
	SubjectFormatEnumeration subjectType;
	
	@Nullable @Column(name="SSR_SSLKEY", length = 512)
	String sslKey;
	
	@Nullable @Column(name="SSR_SSLPUB", length = 512)
	String sslPublicKey;
	
	@Nullable @Column(name="SSR_SSLCER", length = 64000)
	String sslCertificate;

	@Nullable
	Integer queueSize;

	@Nullable
	SubjectSourceEnumeration sourceType;
	
	@Nullable
	String sourceExpression;
	
	@Nullable
	String sourceOAuth;
	
	@Nullable
	String system;
}

