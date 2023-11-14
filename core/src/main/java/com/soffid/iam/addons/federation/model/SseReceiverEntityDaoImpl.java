package com.soffid.iam.addons.federation.model;

import java.util.LinkedList;

import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEntityDaoBase;

public class SseReceiverEntityDaoImpl extends SseReceiverEntityDaoBase {

	@Override
	public void toSseReceiver(SseReceiverEntity source, SseReceiver target) {
		super.toSseReceiver(source, target);
		target.setEvents(new LinkedList<>());
		for (SseReceiverEventEntity ev: source.getEvents())
			target.getEvents().add(ev.getName());
		target.setToken(Digest.decode(source.getToken()));
	}

	@Override
	public void sseReceiverToEntity(SseReceiver source, SseReceiverEntity target, boolean copyIfNull) {
		super.sseReceiverToEntity(source, target, copyIfNull);
		target.setToken(source.getToken() == null ? null: source.getToken().toString());
		target.setSourceSystem(source.getSourceSystem() == null || source.getSourceSystem().trim().isEmpty()? 
				null :
				getSystemEntityDao().findByName(source.getSourceSystem()));
	}


}
