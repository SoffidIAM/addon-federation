package com.soffid.iam.addons.federation.api;

import java.util.Date;

import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class SseSubscription {
	@Nullable @Identifier
	Long id;
	
	String receiver;
	
	@Nullable
	String subject;
	
	Date date;

}
