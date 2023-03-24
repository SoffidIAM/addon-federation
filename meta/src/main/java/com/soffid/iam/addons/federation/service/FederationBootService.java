//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import com.soffid.iam.service.CertificateValidationService;
import com.soffid.iam.service.CrudRegistryService;
import com.soffid.mda.annotation.*;

import org.springframework.transaction.annotation.Transactional;

@Service ( translatedName="FederationBootService",
	 translatedPackage="com.soffid.iam.addons.federation.service")
@Depends ({com.soffid.iam.addons.federation.service.FederationService.class, UserBehaviorService.class, UserCredentialService.class,
	CertificateValidationService.class, 
	SelfCertificateValidationService.class,
	CrudRegistryService.class})
public abstract class FederationBootService extends es.caib.seycon.ng.servei.ApplicationBootService {

}
