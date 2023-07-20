//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEventEntity;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.service.AsyncRunnerService;
import com.soffid.iam.service.CertificateValidationService;
import com.soffid.iam.service.CrudRegistryService;
import com.soffid.mda.annotation.*;

import roles.sse_read;
import roles.sse_update;

import org.springframework.transaction.annotation.Transactional;

@Service
@Depends ({com.soffid.iam.addons.federation.service.FederationService.class, UserBehaviorService.class, UserCredentialService.class,
	CertificateValidationService.class, 
	SelfCertificateValidationService.class,
	CrudRegistryService.class,
	PushAuthenticationService.class,
	SseReceiverEntity.class,
	SseReceiverEventEntity.class,
	AsyncRunnerService.class})
public class SharedSignalEventsService  {
	@Operation(grantees = {sse_read.class})
	public AsyncList<SseReceiver> findReceiverAsync(@Nullable String query) { return null;}

	@Operation(grantees = {sse_read.class})
	public PagedResult<SseReceiver> findReceiver(@Nullable String query, @Nullable Integer first, 
			@Nullable Integer pageSize) { return null;}

	@Operation(grantees = {sse_update.class})
	public SseReceiver create(SseReceiver receiver) { return null;}

	@Operation(grantees = {sse_update.class})
	public SseReceiver update(SseReceiver receiver) { return null;}
	
	@Operation(grantees = {sse_update.class})
	public void delete(SseReceiver receiver) {}
}
