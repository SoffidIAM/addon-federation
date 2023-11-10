package com.soffid.iam.addons.federation.service;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
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
import com.soffid.iam.bpm.service.scim.ScimHelper;
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
		dao.create(entity);
		
		updateEvents(entity, receiver);
		return getSseReceiverEntityDao().toSseReceiver(entity);
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
		if (entity != null)
			getSseReceiverEntityDao().remove(receiver.getId());
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
