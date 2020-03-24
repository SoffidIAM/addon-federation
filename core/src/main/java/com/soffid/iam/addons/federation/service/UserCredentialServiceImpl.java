package com.soffid.iam.addons.federation.service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.api.User;
import com.soffid.iam.model.ConfigEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.utils.AutoritzacionsUsuari;

public class UserCredentialServiceImpl extends UserCredentialServiceBase {

	@Override
	protected UserCredential handleCheck(String challenge, Map<String, Object> response) throws Exception {
		// TODO Auto-generated method stub
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
		UserCredentialEntity entity = getUserCredentialEntityDao().findBySerialNumber(credential);
		if ( entity == null )
			return null;
		else
			return getUserCredentialEntityDao().toUserCredential(entity);
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
		User u = AutoritzacionsUsuari.getCurrentUsuari();
		if (u == null)
			return;

		UserCredentialEntity entity = getUserCredentialEntityDao().load(credential.getId());
		if (entity.getUserId().equals(u.getId()))
			getUserCredentialEntityDao().remove(entity);
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

}
