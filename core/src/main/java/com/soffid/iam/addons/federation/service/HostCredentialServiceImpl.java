package com.soffid.iam.addons.federation.service;

import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.addons.federation.api.HostCredential;
import com.soffid.iam.addons.federation.api.HostCredential;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.HostCredentialEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.api.User;
import com.soffid.iam.model.ConfigEntity;
import com.soffid.iam.model.HostEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.utils.AutoritzacionsUsuari;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

public class HostCredentialServiceImpl extends HostCredentialServiceBase {

	@Override
	protected HostCredential handleUpdateLastUse(HostCredential uc) throws Exception {
		HostCredentialEntity uce = getHostCredentialEntityDao().load(uc.getId());
		if (uce != null) {
			uce.setLastUse(new Date());
			getHostCredentialEntityDao().update(uce);
			return getHostCredentialEntityDao().toHostCredential(uce);
		}
		else
			return null;
	}

	@Override
	protected List<HostCredential> handleFindHostCredentials(String user) throws Exception {
		HostEntity userEntity = getHostEntityDao().findByName(user);
		if (userEntity == null)
			return new LinkedList<HostCredential>();

		Collection<HostCredentialEntity> l = getHostCredentialEntityDao().findByHostId(userEntity.getId());
		return getHostCredentialEntityDao().toHostCredentialList(l);
	}

	@Override
	protected void handleRemove(HostCredential credential) throws Exception {
		HostCredentialEntity entity = getHostCredentialEntityDao().load(credential.getId());
		getHostCredentialEntityDao().remove(entity);
	}
	
	@Override
	protected String handleGenerateNextSerial() throws Exception {
		ConfigEntity data = getConfigEntityDao().findByCodeAndNetworkCode("federation.host-credential.next-serial", null);
		if (data == null)
		{
			data = getConfigEntityDao().newConfigEntity();
			data.setDescription("Host credential serial generator");
			data.setName("federation.host-credential.next-serial");
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
