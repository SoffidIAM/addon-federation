//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SseSubscription;
import com.soffid.iam.addons.federation.model.SseEventEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEventEntity;
import com.soffid.iam.addons.federation.model.SseSubscriptionEntity;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.service.AsyncRunnerService;
import com.soffid.iam.service.CertificateValidationService;
import com.soffid.iam.service.CrudRegistryService;
import com.soffid.mda.annotation.*;

import es.caib.seycon.ng.servei.DispatcherService;
import es.caib.seycon.ng.model.DispatcherEntity;
import es.caib.seycon.ng.model.DominiContrasenyaEntity;
import es.caib.seycon.ng.model.DominiUsuariEntity;
import es.caib.seycon.ng.servei.DominiUsuariService;
import es.caib.seycon.ng.servei.SeyconServerService;
import roles.sse_read;
import roles.sse_update;

import java.util.List;

import org.springframework.transaction.annotation.Transactional;

@Service(serverPath = "/seycon/SharedSignalEventsService", serverRole="agent")
@Depends ({
	SseSubscriptionEntity.class,
	SseReceiverEntity.class,
	SseReceiverEventEntity.class,
	SseEventEntity.class,
	DispatcherService.class,
	AsyncRunnerService.class,
	DispatcherEntity.class,
	DominiContrasenyaEntity.class,
	DominiUsuariEntity.class,
	SeyconServerService.class})
public class SharedSignalEventsService  {
	@Operation(grantees = {sse_read.class})
	public AsyncList<SseReceiver> findReceiverAsync(@Nullable String textQuery, @Nullable String query) { return null;}

	@Operation(grantees = {sse_read.class})
	public PagedResult<SseReceiver> findReceiver(@Nullable String textQuery, @Nullable String query, @Nullable Integer first, 
			@Nullable Integer pageSize) { return null;}

	@Operation(grantees = {sse_update.class})
	public SseReceiver create(SseReceiver receiver) { return null;}

	@Operation(grantees = {sse_update.class})
	public SseReceiver update(SseReceiver receiver) { return null;}
	
	@Operation(grantees = {sse_update.class})
	public void delete(SseReceiver receiver) {}
	
	// Subscriptions
	public void addSubscription (SseSubscription s) {}
	public void removeSubscription (SseSubscription s) {}
	public void clearSubscriptions (SseReceiver receiver) {}
	public List<SseSubscription> findSubscriptions(SseReceiver receiver, String subject) {return null;}
	public List<SseSubscription> findSubscriptions(SseReceiver receiver) {return null;}
	
	// Events
	public void addEvent (SseEvent s) {}
	public List<SseEvent> popEvents (SseReceiver receiver, @Nullable Integer maxEvents) {return null;}
	public List<SseEvent> fetchEvents (SseReceiver receiver, @Nullable Integer maxEvents) {return null;}
	public void removeEvent (Long eventId) {}
}
