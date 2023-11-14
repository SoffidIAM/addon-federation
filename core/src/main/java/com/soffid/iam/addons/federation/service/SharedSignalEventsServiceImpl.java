package com.soffid.iam.addons.federation.service;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.json.JSONException;

import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.FederationMemberEntityDao;
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEntityDao;
import com.soffid.iam.addons.federation.model.SseReceiverEventEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEventEntityDao;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.api.UserDomain;
import com.soffid.iam.bpm.service.scim.ScimHelper;
import com.soffid.iam.model.PasswordDomainEntity;
import com.soffid.iam.model.SystemEntity;
import com.soffid.iam.model.UserDomainEntity;
import com.soffid.iam.model.criteria.CriteriaSearchConfiguration;
import com.soffid.iam.service.AdditionalDataJSONConfiguration;
import com.soffid.scimquery.EvalException;
import com.soffid.scimquery.parser.ParseException;
import com.soffid.scimquery.parser.TokenMgrError;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SharedSignalEventsServiceImpl extends SharedSignalEventsServiceBase {

	@Override
	protected SseReceiver handleCreate(SseReceiver receiver) throws Exception {
		SseReceiverEntityDao dao = getSseReceiverEntityDao();
		SseReceiverEntity entity = dao.sseReceiverToEntity(receiver);
		
		SystemEntity s = registerSystem(receiver);
		
		entity.setSystem(s);
		getSseReceiverEntityDao().create(entity);
		
		updateEvents(entity, receiver);
		return getSseReceiverEntityDao().toSseReceiver(entity);
	}

	protected SystemEntity registerSystem(SseReceiver receiver) {
		SystemEntity s = getSystemEntityDao().newSystemEntity();
		s.setName(findEmptyName(receiver.getName()));
		s.setAuthoritative(false);
		s.setClassName("com.soffid.iam.federation.agent.SseAgent");
		s.setDescription("SSE Receiver "+receiver.getName());
		s.setEnableAccessControl("N");
		s.setSharedDispatcher(true);
		s.setManualAccountCreation(true);
		s.setPasswordDomain(findDefaultPasswordDomain());
		s.setTimeStamp(new Date());
		s.setTrusted("N");
		s.setUrl("local");
		s.setUserDomain(findDefaultUserDomain());
		getSystemEntityDao().create(s);
		return s;
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

	private String findEmptyName(String name) {
		String prefix = "sse:"+name;
		String candidate = prefix;
		int i = 1;
		do {
			if ( getSystemEntityDao().findByName(candidate) == null)
				return candidate;
			i ++;
			candidate = prefix+"_"+i;
		} while (true);
	}

	protected void updateEvents(SseReceiverEntity entity, SseReceiver receiver) {
		SseReceiverEventEntityDao eventDao = getSseReceiverEventEntityDao();
		if (entity.getEvents() != null) {
			eventDao.remove(entity.getEvents());
			entity.getEvents().clear();
		}
		if (receiver.getEvents() != null) {
			for (String event: receiver.getEvents()) {
				if (event != null && !event.trim().isEmpty()) {
					SseReceiverEventEntity e = eventDao.newSseReceiverEventEntity();
					e.setName(event);
					e.setReceiver(entity);
					eventDao.create(e);
					entity.getEvents().add(e);
				}
			}
		}
	}

	@Override
	protected SseReceiver handleUpdate(SseReceiver receiver) throws Exception {
		SseReceiverEntityDao dao = getSseReceiverEntityDao();
		SseReceiverEntity entity = dao.sseReceiverToEntity(receiver);
		dao.update(entity);
		
		SystemEntity system = entity.getSystem();
		if (system == null) {
			system = registerSystem(receiver);
			entity.setSystem(system);
		}
		else if (! system.getName().startsWith("sse:"+receiver.getName()+"_") &&
				!system.getName().equals("sse:"+receiver.getName())) {
			system.setName(findEmptyName("sse:"+receiver.getName()));
			system.setTimeStamp(new Date());
			getSystemEntityDao().update(system);
		}
		
		updateEvents(entity, receiver);
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
			com.soffid.iam.api.System system = null;
			if (entity.getSystem() != null) {
				system = getSystemEntityDao().toSystem(entity.getSystem());
			}
			getSseReceiverEntityDao().remove(receiver.getId());
			if (system != null)
				getDispatcherService().delete(system);
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

}
