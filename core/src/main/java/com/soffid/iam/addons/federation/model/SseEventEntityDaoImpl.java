package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.api.SseEvent;

public class SseEventEntityDaoImpl extends SseEventEntityDaoBase {

	@Override
	public void toSseEvent(SseEventEntity source, SseEvent target) {
		super.toSseEvent(source, target);
		target.setReceiver(source.getReceiver() == null ? null: source.getReceiver().getName());
	}

	@Override
	public void sseEventToEntity(SseEvent source, SseEventEntity target, boolean copyIfNull) {
		super.sseEventToEntity(source, target, copyIfNull);
		target.setReceiver(getSseReceiverEntityDao().findByName(source.getReceiver()));
	}

}
