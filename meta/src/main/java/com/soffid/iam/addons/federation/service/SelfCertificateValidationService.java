//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import com.soffid.iam.addons.federation.model.RootCertificateEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.service.CertificateValidationService;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Service;

@Service ( internal=true)
@Depends ({SelfCertificateService.class,
	RootCertificateEntity.class,
	UserCredentialEntity.class,
	es.caib.seycon.ng.servei.UsuariService.class})
public class SelfCertificateValidationService extends CertificateValidationService {
	
}
