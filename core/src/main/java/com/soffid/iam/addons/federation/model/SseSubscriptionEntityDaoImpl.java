package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.api.SseSubscription;

public class SseSubscriptionEntityDaoImpl extends SseSubscriptionEntityDaoBase {

	@Override
	public void toSseSubscription(SseSubscriptionEntity source, SseSubscription target) {
		super.toSseSubscription(source, target);
		target.setReceiver(source.getReceiver().getName());
	}

	@Override
	public void sseSubscriptionToEntity(SseSubscription source, SseSubscriptionEntity target, boolean copyIfNull) {
		super.sseSubscriptionToEntity(source, target, copyIfNull);
		target.setReceiver(getSseReceiverEntityDao().findByName(source.getReceiver()));
	}

	@Override
	protected void handleRemoveByReceiver(String receiver) throws Exception {
		getSession().createQuery("delete from com.soffid.iam.addons.federation.model.SseSubscriptionEntity "
				+ "where receiver.id in "
				+ "(select id from com.soffid.iam.addons.federation.model.SseReceiverEntity as r where r.name = :receiver)")
			.setString("receiver", receiver)
			.executeUpdate();
	}

}
