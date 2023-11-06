//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import java.util.Date;

import org.springframework.transaction.annotation.Transactional;

import com.soffid.iam.addons.federation.model.HostCredentialEntity;
import com.soffid.iam.addons.federation.model.RootCertificateEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.service.CertificateValidationService;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.comu.Maquina;
import es.caib.seycon.ng.servei.XarxaService;

@Service ( internal=true)
@Depends ({SelfCertificateService.class,
	RootCertificateEntity.class,
	UserCredentialEntity.class,
	HostCredentialEntity.class,
	XarxaService.class,
	es.caib.seycon.ng.servei.UsuariService.class})
public class SelfCertificateValidationService extends CertificateValidationService {
	@Transactional(rollbackFor={java.lang.Exception.class})
	public Maquina getCertificateHost(
		java.util.List<java.security.cert.X509Certificate> certs,
		@Nullable String serialNumber)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Transactional(rollbackFor={java.lang.Exception.class})
	public Date getCertificateExpirationWarning(
		java.util.List<java.security.cert.X509Certificate> certs)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
}
