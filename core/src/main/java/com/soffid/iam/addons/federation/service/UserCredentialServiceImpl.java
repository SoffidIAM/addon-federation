package com.soffid.iam.addons.federation.service;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.IdentityProviderEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.addons.federation.model.UserCredentialRequestEntity;
import com.soffid.iam.api.User;
import com.soffid.iam.model.ConfigEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.utils.AutoritzacionsUsuari;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

public class UserCredentialServiceImpl extends UserCredentialServiceBase {

	@Override
	protected UserCredential handleCheck(String challenge, Map<String, Object> response) throws Exception {
		return null;
	}

	@Override
	protected UserCredential handleCreate(UserCredential credential) throws Exception {
		UserCredentialEntity entity = getUserCredentialEntityDao().newUserCredentialEntity();
		getUserCredentialEntityDao().userCredentialToEntity(credential, entity, true);
		getUserCredentialEntityDao().create(entity);
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
		if (canRemove(entity))
			getUserCredentialEntityDao().remove(entity);

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
	protected URI handleGenerateNewCredential() throws Exception {
		return handleGenerateNewCredential(Security.getCurrentUser(), false, null, null);
	}

	@Override
	protected URI handleGenerateNewCredential(String userName, boolean unsecure, Date activateBefore, String identityProvider) throws Exception {
		getUserCredentialRequestEntityDao().deleteExpired();
		UserCredentialRequestEntity c = getUserCredentialRequestEntityDao().newUserCredentialRequestEntity();
		byte b[] = new byte[66];
		if (! unsecure) {
			String hash;
			do {
				new SecureRandom().nextBytes(b);
				hash = Base64.getUrlEncoder().encodeToString(b);
			} while ( getUserCredentialRequestEntityDao().findByHash(hash) != null);
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
		getUserCredentialRequestEntityDao().create(c);
		
		for (FederationMemberEntity fm: getFederationMemberEntityDao().findFMByEntityGroupAndPublicIdAndTipus("%", "%", "I")) {
			if (fm instanceof IdentityProviderEntity) {
				final IdentityProviderEntity idp = (IdentityProviderEntity) fm;
				if (idp.getIdpType() == IdentityProviderType.SOFFID && 
						(identityProvider == null || identityProvider.trim().isEmpty() || identityProvider.equals(idp.getPublicId()))) {
					if (!unsecure)
						return new URI(
								Boolean.TRUE.equals(idp.getDisableSSL()) ? "http": "https",
								null, // User
								idp.getHostName(),
								Integer.parseInt(idp.getStandardPort()),
								"/registerRequestedCredential/"+c.getHash(),
								null, // Query
								null  // Hash
								);
					else
						return new URI(
								Boolean.TRUE.equals(idp.getDisableSSL()) ? "http": "https",
								null, // User
								idp.getHostName(),
								Integer.parseInt(idp.getStandardPort()),
								"/protected/registerCredential",
								null, // Query
								null  // Hash
								);
				}
			}
		}
		throw new InternalErrorException("Cannot find a valid identity provider to register the user");
	}

	@Override
	protected void handleCancelNewCredentialURI(String hash) throws Exception {
		UserCredentialRequestEntity r = getUserCredentialRequestEntityDao().findByHash(hash);
		if (r != null)
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
			if (r.getHash() == null && r.getExpiration().getTime() > System.currentTimeMillis())
			{
				getUserCredentialRequestEntityDao().remove(r);
				break;
			}
		}
	}

}
