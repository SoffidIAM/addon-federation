package com.soffid.iam.addons.federation.service;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.beanutils.PropertyUtils;
import org.json.JSONException;

import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SseSubscription;
import com.soffid.iam.addons.federation.model.SseEventEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEntityDao;
import com.soffid.iam.addons.federation.model.SseReceiverEventEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEventEntityDao;
import com.soffid.iam.addons.federation.model.SseSubscriptionEntity;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.bpm.service.scim.ScimHelper;
import com.soffid.iam.model.PasswordDomainEntity;
import com.soffid.iam.model.SystemEntity;
import com.soffid.iam.model.UserDomainEntity;
import com.soffid.iam.model.criteria.CriteriaSearchConfiguration;
import com.soffid.scimquery.EvalException;
import com.soffid.scimquery.parser.ParseException;
import com.soffid.scimquery.parser.TokenMgrError;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SharedSignalEventsServiceImpl extends SharedSignalEventsServiceBase {

	@Override
	protected SseReceiver handleCreate(SseReceiver receiver) throws Exception {
		SseReceiverEntityDao dao = getSseReceiverEntityDao();
		SseReceiverEntity entity = dao.sseReceiverToEntity(receiver);
		
		getSseReceiverEntityDao().create(entity);
		
		updateEvents(entity, receiver);
		getSyncServerService().updateDispatcherConfiguration();
		return getSseReceiverEntityDao().toSseReceiver(entity);
	}

	private PasswordDomainEntity findDefaultPasswordDomain() {
		PasswordDomainEntity def = getPasswordDomainEntityDao().findByName("DEFAULT");
		if (def != null)
			return def;
		return getPasswordDomainEntityDao().loadAll().iterator().next();
	}

	private UserDomainEntity findDefaultUserDomain() {
		UserDomainEntity def = getUserDomainEntityDao().findByName("DEFAULT");
		if (def != null)
			return def;
		return getUserDomainEntityDao().loadAll().iterator().next();
	}

	protected void updateEvents(SseReceiverEntity entity, SseReceiver receiver) {
		SseReceiverEventEntityDao eventDao = getSseReceiverEventEntityDao();
		if (entity.getEvents() != null) {
			eventDao.remove(entity.getAllowedEvents());
			entity.getEvents().clear();
		}
		if (receiver.getEvents() != null) {
			for (String event: receiver.getEvents()) {
				if (event != null && !event.trim().isEmpty()) {
					SseReceiverEventEntity e = eventDao.newSseReceiverEventEntity();
					e.setName(event);
					e.setReceiver(entity);
					eventDao.create(e);
					entity.getAllowedEvents().add(e);
				}
			}
		}
	}

	@Override
	protected SseReceiver handleUpdate(SseReceiver receiver) throws Exception {
		SseReceiverEntityDao dao = getSseReceiverEntityDao();
		SseReceiverEntity entity = dao.sseReceiverToEntity(receiver);
		dao.update(entity);
		
		updateEvents(entity, receiver);
		getSyncServerService().updateDispatcherConfiguration();
		return getSseReceiverEntityDao().toSseReceiver(entity);
	}

	@Override
	protected AsyncList<SseReceiver> handleFindReceiverAsync(String textQuery, String query) throws Exception {
		AsyncList<SseReceiver> l = new AsyncList<>();
		getAsyncRunnerService().run(() -> {
			try {
				internalSearchByJson(textQuery, query, l, null, null);
			} catch (Throwable e) {
				throw new RuntimeException(e);
			}				
		}, l );
		return l;
	}

	@Override
	protected PagedResult<SseReceiver> handleFindReceiver(String textQuery, String query, Integer first, Integer pageSize)
			throws Exception {
		LinkedList<SseReceiver> r = new LinkedList<>();
		return internalSearchByJson(textQuery, query, r, first, pageSize);
	}

	@Override
	protected void handleDelete(SseReceiver receiver) throws Exception {
		SseReceiverEntity entity = getSseReceiverEntityDao().load(receiver.getId());
		if (entity != null) {
			getSseReceiverEntityDao().remove(receiver.getId());
			getSyncServerService().updateDispatcherConfiguration();
		}
	}

	private PagedResult<SseReceiver> internalSearchByJson(String textQuery, String query, List<SseReceiver> result, 
			Integer first,
			Integer pageSize) throws UnsupportedEncodingException, ClassNotFoundException, JSONException, InternalErrorException, EvalException, ParseException, TokenMgrError {
		// Register virtual attributes for additional data
		final SseReceiverEntityDao dao = getSseReceiverEntityDao();
		ScimHelper h = new ScimHelper(SseReceiver.class);
		h.setPrimaryAttributes(new String[] { "name", "description"} );
		
		CriteriaSearchConfiguration config = new CriteriaSearchConfiguration();
		config.setFirstResult(first);
		config.setMaximumResultSize(pageSize);
		h.setConfig(config);
		h.setTenantFilter("tenant.id");
		h.setGenerator((entity) -> {
			return dao.toSseReceiver((SseReceiverEntity) entity);
		});
		
		h.search(textQuery, query, (Collection) result); 

		PagedResult<SseReceiver> pr = new PagedResult<>();
		pr.setStartIndex(first);
		pr.setItemsPerPage(pageSize);
		pr.setTotalResults(h.count());
		pr.setResources(result);
		return pr;
	}

	@Override
	protected List<SseEvent> handleFetchEvents(SseReceiver receiver, Integer max) throws Exception {
		CriteriaSearchConfiguration criteria = new CriteriaSearchConfiguration();
		criteria.setMaximumResultSize(max);
		List<SseEventEntity> l = getSseEventEntityDao().findByReceiver(receiver.getName());
		List<SseEvent> l2 = getSseEventEntityDao().toSseEventList(l);
		return l2;
	}

	@Override
	protected List<SseEvent> handlePopEvents(SseReceiver receiver, Integer max) throws Exception {
		CriteriaSearchConfiguration criteria = new CriteriaSearchConfiguration();
		criteria.setMaximumResultSize(max);
		List<SseEventEntity> l = getSseEventEntityDao().findByReceiver(criteria , receiver.getName());
		List<SseEvent> l2 = getSseEventEntityDao().toSseEventList(l);
		getSseEventEntityDao().remove(l);
		return l2;
	}

	@Override
	protected List<SseSubscription> handleFindSubscriptions(SseReceiver receiver) throws Exception {
		List<SseSubscriptionEntity> l = getSseSubscriptionEntityDao().findByReceiver(receiver.getName());
		List<SseSubscription> r = getSseSubscriptionEntityDao().toSseSubscriptionList(l);
		return r;
	}

	@Override
	protected void handleAddEvent(SseEvent s) throws Exception {
		SseReceiverEntity r = getSseReceiverEntityDao().findByName(s.getReceiver());
		if (r == null)
			throw new InternalErrorException("Wrong receiver "+s.getReceiver());
		Long count = getSseEventEntityDao().countByReceiver(s.getReceiver());
		if (count != null && r.getQueueSize() != null && count.intValue() >= r.getQueueSize()) {
			CriteriaSearchConfiguration criteria = new CriteriaSearchConfiguration();
			criteria.setMaximumResultSize(count.intValue() - r.getQueueSize() + 1);
			List<SseEventEntity> l = getSseEventEntityDao().findByReceiver(criteria , s.getReceiver());
			getSseEventEntityDao().remove(l);
		}
		SseEventEntity entity = getSseEventEntityDao().sseEventToEntity(s);
		getSseEventEntityDao().create(entity);
	}

	@Override
	protected void handleAddSubscription(SseSubscription s) throws Exception {
		SseSubscriptionEntity entity = getSseSubscriptionEntityDao().sseSubscriptionToEntity(s);
		getSseSubscriptionEntityDao().create(entity);
	}

	@Override
	protected void handleRemoveSubscription(SseSubscription s) throws Exception {
		getSseSubscriptionEntityDao().remove(s.getId());
	}

	@Override
	protected List<SseSubscription> handleFindSubscriptions(SseReceiver receiver, String subject) throws Exception {
		List<SseSubscriptionEntity> l = getSseSubscriptionEntityDao()
				.findByReceiverAndUserName(receiver.getName(), subject);
		return getSseSubscriptionEntityDao().toSseSubscriptionList(l);
	}

	@Override
	protected void handleClearSubscriptions(SseReceiver receiver) throws Exception {
		getSseSubscriptionEntityDao().removeByReceiver(receiver.getName());
	}

	@Override
	protected void handleRemoveEvent(Long eventId) throws Exception {
		getSseEventEntityDao().remove(eventId);
	}

	@Override
	protected void handleAddEventTemplate(SseEvent s) throws Exception {
		for (SseReceiverEntity receiver: getSseReceiverEntityDao().findByEventType(s.getType())) {
			SseEvent ev = new SseEvent(s);
			ev.setReceiver(receiver.getName());
			handleAddEvent(ev);
		}
	}

}
