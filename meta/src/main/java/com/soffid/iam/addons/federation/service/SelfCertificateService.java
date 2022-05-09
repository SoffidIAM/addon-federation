//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.model.RootCertificateEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.mda.annotation.*;

import roles.Tothom;
import roles.selfcertificate_query;

import org.springframework.transaction.annotation.Transactional;

@Service ( )
@Depends ({es.caib.seycon.ng.servei.ConfiguracioService.class,
	UserCredentialEntity.class,
	RootCertificateEntity.class,
	es.caib.seycon.ng.model.UsuariEntity.class,
	UserCredentialService.class})
public abstract class SelfCertificateService {

	@Operation ( grantees={selfcertificate_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.List<UserCredential> findByUser(
		java.lang.String user)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={roles.selfcertificate_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public UserCredential findByCertificate(
		java.security.cert.X509Certificate certificate)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={roles.selfcertificate_user.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.security.cert.X509Certificate create(
		java.lang.String description, 
		java.lang.String pkcs10)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={roles.selfcertificate_user.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public byte[] createPkcs12(
		java.lang.String description, 
		java.lang.String pasword)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={roles.selfcertificate_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public byte[] createPkcs12(
		String user,
		java.lang.String description, 
		java.lang.String pasword)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={roles.selfcertificate_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.RootCertificate createRootCertificate(
		com.soffid.iam.addons.federation.common.RootCertificate root)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={roles.selfcertificate_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void revokeRootCertificate(
		com.soffid.iam.addons.federation.common.RootCertificate root)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={roles.selfcertificate_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void updateRootCertificate(
		com.soffid.iam.addons.federation.common.RootCertificate root)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={roles.selfcertificate_manage.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.List<com.soffid.iam.addons.federation.common.RootCertificate> getRootCertificates()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={Tothom.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.security.cert.X509Certificate getRootCertificate()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={Tothom.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public int getUserCertificateDuration()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return 0;
	}
}
