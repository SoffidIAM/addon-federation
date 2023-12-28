package com.soffid.iam.addons.federation.model;

import java.util.LinkedList;
import java.util.List;

import org.apache.commons.beanutils.PropertyUtils;

import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEntityDaoBase;
import com.soffid.iam.model.SystemEntity;

public class SseReceiverEntityDaoImpl extends SseReceiverEntityDaoBase {
	@Override
	public void toSseReceiver(SseReceiverEntity source, SseReceiver target) {
		super.toSseReceiver(source, target);
		target.setEvents(new LinkedList<>());
		for (SseReceiverEventEntity ev: source.getAllowedEvents())
			target.getEvents().add(ev.getName());
		target.setToken(Digest.decode(source.getToken()));
		target.setIdentityProvider(source.getIdentityProvider() == null ? null : source.getIdentityProvider().getPublicId());
		target.setServiceProvider(source.getServiceProvider() == null ? null: source.getServiceProvider().getPublicId());
		target.setSourceSystem(source.getSourceSystem() == null ? null: source.getSourceSystem().getName());
	}

	@Override
	public void sseReceiverToEntity(SseReceiver source, SseReceiverEntity target, boolean copyIfNull) {
		super.sseReceiverToEntity(source, target, copyIfNull);
		target.setToken(source.getToken() == null ? null: source.getToken().toString());
		target.setSourceSystem(source.getSourceSystem() == null || source.getSourceSystem().trim().isEmpty()? 
				null :
				getSystemEntityDao().findByName(source.getSourceSystem()));
		target.setIdentityProvider(null);
		for (FederationMemberEntity fm: getIdentityProviderEntityDao().findFMByPublicId(source.getIdentityProvider())) {
			if (fm instanceof IdentityProviderEntity)
				target.setIdentityProvider((IdentityProviderEntity) fm);
		}
		if (source.getServiceProvider() == null)
			target.setServiceProvider(null);
		else {
			for (FederationMemberEntity fm: getServiceProviderEntityDao().findFMByPublicId(source.getServiceProvider())) {
				if (fm instanceof ServiceProviderEntity)
					target.setServiceProvider((ServiceProviderEntity) fm);
			}
		}
	}


}
