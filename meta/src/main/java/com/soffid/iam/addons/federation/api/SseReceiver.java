package com.soffid.iam.addons.federation.api;

import java.util.Date;
import java.util.List;

import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.mda.annotation.Attribute;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.JsonAttribute;
import com.soffid.mda.annotation.JsonObject;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

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
}
