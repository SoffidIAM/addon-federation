package com.soffid.iam.addons.federation.service;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.IdentityProviderEntity;
import com.soffid.iam.addons.federation.model.IdpNetworkConfigEntity;
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.addons.federation.model.UserCredentialRequestEntity;
import com.soffid.iam.api.User;
import com.soffid.iam.model.ConfigEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.utils.AutoritzacionsUsuari;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

public class UserCredentialServiceImpl extends UserCredentialServiceBase {

	private static final String CAEP_EVENT_NAME = "https://schemas.openid.net/secevent/caep/event-type/credential-change";

	@Override
	protected UserCredential handleCheck(String challenge, Map<String, Object> response) throws Exception {
		return null;
	}

	@Override
	protected UserCredential handleCreate(UserCredential credential) throws Exception {
		UserCredentialEntity entity = getUserCredentialEntityDao().newUserCredentialEntity();
		getUserCredentialEntityDao().userCredentialToEntity(credential, entity, true);
		getUserCredentialEntityDao().create(entity);

		generateCaepEvent(credential, "create");
		
		return getUserCredentialEntityDao().toUserCredential(entity);
	}

	@Override
	protected UserCredential handleFindBySerial(String credential) throws Exception {
		for (UserCredentialEntity entity: getUserCredentialEntityDao().findBySerialNumber(credential)) {
			if (entity.getType() == UserCredentialType.FIDO)
				return getUserCredentialEntityDao().toUserCredential(entity);
		}
		return null;
	}

	@Override
	protected String handleGenerateChallenge() throws Exception {
		byte[] b = new byte [64];
		new SecureRandom().nextBytes(b);
		
		return Base64.getEncoder().encodeToString(b);
	}

	@Override
	protected List<UserCredential> handleFindMyCredentials() throws Exception {
		User u = AutoritzacionsUsuari.getCurrentUsuari();
		if (u == null)
			return new LinkedList<UserCredential>();
		
		Collection<UserCredentialEntity> l = getUserCredentialEntityDao().findByUserId(u.getId());
		return getUserCredentialEntityDao().toUserCredentialList(l);
	}

	@Override
	protected List<UserCredential> handleFindUserCredentials(String user) throws Exception {
		UserEntity userEntity = getUserEntityDao().findByUserName(user);
		if (userEntity == null)
			return new LinkedList<UserCredential>();

		Collection<UserCredentialEntity> l = getUserCredentialEntityDao().findByUserId(userEntity.getId());
		return getUserCredentialEntityDao().toUserCredentialList(l);
	}

	@Override
	protected void handleRemove(UserCredential credential) throws Exception {
		UserCredentialEntity entity = getUserCredentialEntityDao().load(credential.getId());
		if (canRemove(entity)) {
			generateCaepEvent(credential, "remove");
			getUserCredentialEntityDao().remove(entity);
		}
	}

	protected void generateCaepEvent(UserCredential credential, String action) throws InternalErrorException {
		UserEntity userEntity = getUserEntityDao().load(credential.getUserId());
		if (userEntity != null) {
			for (SseReceiverEntity receiver: getSseReceiverEntityDao().findByEventType(CAEP_EVENT_NAME)) {
				SseEvent ev = new SseEvent();
				ev.setType(CAEP_EVENT_NAME);
				ev.setUser(userEntity.getUserName());
				ev.setReceiver(receiver.getName());
				ev.setDate(new Date());
				ev.setCredentialType(credential.getType() == UserCredentialType.CERT ? "x509":
								credential.getType() == UserCredentialType.FIDO ? "fido2-roaming":
										"app");
				ev.setChangeType(action);
				
				if (credential.getType() == UserCredentialType.CERT && credential.getCertificate() != null) {
					ev.setX509Serial(credential.getCertificate().getSerialNumber().toString());
					ev.setX509Issuer(credential.getCertificate().getIssuerX500Principal().getName());
					getSharedSignalEventsService().addEvent(ev);
				}
				if (credential.getType() == UserCredentialType.FIDO) {
					ev.setFido2aaGuid(credential.getSerialNumber());
					getSharedSignalEventsService().addEvent(ev);
				}
				
			}
		}
	}

	private boolean canRemove(UserCredentialEntity entity) throws InternalErrorException {
		if (Security.isUserInRole("federation-credential:remove"))
			return true;
		User u = AutoritzacionsUsuari.getCurrentUsuari();
		if (u == null)
			return false;
		return entity.getUserId().equals(u.getId()); 
	}

	@Override
	protected String handleGenerateNextSerial() throws Exception {
		ConfigEntity data = getConfigEntityDao().findByCodeAndNetworkCode("federation.user-credential.next-serial", null);
		if (data == null)
		{
			data = getConfigEntityDao().newConfigEntity();
			data.setDescription("User credential serial generator");
			data.setName("federation.user-credential.next-serial");
			data.setValue("1");
			getConfigEntityDao().create(data);
		}
		Long current = Long.decode(data.getValue());
		Long next = new Long (current.longValue() + 1 );
		data.setValue(next.toString());
		getConfigEntityDao().update(data);
		return String.format("%012d", current);
	}

	@Override
	protected User handleFindUserForNewCredentialURI(String hash) throws Exception {
		UserCredentialRequestEntity r = getUserCredentialRequestEntityDao().findByHash(hash);
		if (r == null || r.getExpiration().before(new Date()))
			return null;
		else {
			UserEntity u = getUserEntityDao().load(r.getUserId());
			if (u == null)
				return null; 
			else
				return getUserEntityDao().toUser(u);
		}
	}

	@Override
	protected URI handleGenerateNewCredential( UserCredentialType type) throws Exception {
		return handleGenerateNewCredential(type, Security.getCurrentUser(), false, null, null);
	}

	@Override
	protected URI handleGenerateNewCredential(UserCredentialType type, String userName, boolean unsecure, Date activateBefore, String identityProvider) throws Exception {
		getUserCredentialRequestEntityDao().deleteExpired();
		UserCredentialRequestEntity c = getUserCredentialRequestEntityDao().newUserCredentialRequestEntity();
		byte b[] = new byte[66];
		if (! unsecure) {
			String hash;
			do {
				new SecureRandom().nextBytes(b);
				hash = Base64.getUrlEncoder().encodeToString(b);
			} while ( getUserCredentialRequestEntityDao().findByHash(hash) != null);
			if (type == UserCredentialType.PUSH)
				hash = hash.substring(0, 48);
			c.setHash(hash);
		}
		if (activateBefore == null)
			c.setExpiration(new Date(System.currentTimeMillis() + 8 * 60 * 60 * 1000L)); // Valid for eight hours
		else
			c.setExpiration(activateBefore);
		
		if (userName == null) throw new InternalErrorException("Tokens can only be bound to identities, not shared accounts");
		UserEntity u = getUserEntityDao().findByUserName(userName);
		if (u == null) throw new InternalErrorException("Cannot locate user "+userName);
		c.setUserId(u.getId());
		c.setType(type);
		getUserCredentialRequestEntityDao().create(c);
		
		for (FederationMemberEntity fm: getFederationMemberEntityDao().findFMByEntityGroupAndPublicIdAndTipus("%", "%", "I")) {
			if (fm instanceof IdentityProviderEntity) {
				final IdentityProviderEntity idp = (IdentityProviderEntity) fm;
				if (idp.getIdpType() == IdentityProviderType.SOFFID && 
						(identityProvider == null || identityProvider.trim().isEmpty() || identityProvider.equals(idp.getPublicId()))) {
					for (IdpNetworkConfigEntity cfg: idp.getNetworkConfigs() ) {
						if (type == UserCredentialType.PUSH) {
							URI u2 = new URI(
								"https",
								null, // User
								idp.getHostName(),
								cfg.isProxy() && cfg.getProxyPort() != null ? cfg.getProxyPort(): cfg.getPort(),
								"/rpc/"+c.getHash(),
								null, // Query
								null  // Hash
								);
							return new URI("soffidpush", u2.toString(),
									null);
						}
						else if (!unsecure)
							return new URI(
									"https",
									null, // User
									idp.getHostName(),
									cfg.isProxy() && cfg.getProxyPort() != null ? cfg.getProxyPort(): cfg.getPort(),
									"/registerRequestedCredential/"+c.getHash(),
									null, // Query
									null  // Hash
									);
						else
							return new URI(
									"https",
									null, // User
									idp.getHostName(),
									cfg.isProxy() && cfg.getProxyPort() != null ? cfg.getProxyPort(): cfg.getPort(),
									"/protected/registerCredential",
									null, // Query
									null  // Hash
									);
					}
					throw new InternalErrorException("Unable to find network configuration for the identity provider");
				}
			}
		}
		throw new InternalErrorException("Cannot find a valid identity provider to register the user");
	}

	@Override
	protected void handleCancelNewCredentialURI(String hash) throws Exception {
		UserCredentialRequestEntity r = getUserCredentialRequestEntityDao().findByHash(hash);
		if (r != null  && ! Boolean.TRUE.equals(r.getPersistent()))
			getUserCredentialRequestEntityDao().remove(r);
	}

	@Override
	protected boolean handleCheckUserForNewCredential(String user) throws Exception {
		UserEntity u = getUserEntityDao().findByUserName(user);
		if (!u.getActive().equals("S"))
			return false;
		
		for (UserCredentialRequestEntity r: getUserCredentialRequestEntityDao().findByUser(u.getId())) {
			if (r.getHash() == null && r.getExpiration().getTime() > System.currentTimeMillis())
				return true;
		}
		return false;
	}

	@Override
	protected void handleCancelNewCredentialURIForUser(String user) throws Exception {
		UserEntity u = getUserEntityDao().findByUserName(user);
		
		for (UserCredentialRequestEntity r: getUserCredentialRequestEntityDao().findByUser(u.getId())) {
			if (r.getHash() == null && r.getExpiration().getTime() > System.currentTimeMillis() &&
					! Boolean.TRUE.equals(r.getPersistent()))
			{
				getUserCredentialRequestEntityDao().remove(r);
				break;
			}
		}
	}

	@Override
	protected UserCredential handleUpdateLastUse(UserCredential uc) throws Exception {
		UserCredentialEntity uce = getUserCredentialEntityDao().load(uc.getId());
		if (uce != null) {
			uce.setLastUse(new Date());
			getUserCredentialEntityDao().update(uce);
			return getUserCredentialEntityDao().toUserCredential(uce);
		}
		else
			return null;
	}

}
