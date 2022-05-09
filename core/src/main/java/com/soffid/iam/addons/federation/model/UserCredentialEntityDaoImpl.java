package com.soffid.iam.addons.federation.model;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.SelfCertificate;
import com.soffid.iam.addons.federation.common.UserCredentialType;

import es.caib.seycon.util.Base64;

public class UserCredentialEntityDaoImpl extends UserCredentialEntityDaoBase {
	@Override
	public void toUserCredential(UserCredentialEntity source,
			UserCredential target) {
		super.toUserCredential(source, target);
		try {
			if (source.getCertificate() != null) {
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				ByteArrayInputStream in = new ByteArrayInputStream( Base64.decode(source.getCertificate()));
				target.setCertificate( (X509Certificate) cf.generateCertificate(in));
			}
		} catch (CertificateException e) {
		}
		if (source.getType() == null)
			target.setType(UserCredentialType.FIDO);
	}

	@Override
	public void userCredentialToEntity(UserCredential source,
			UserCredentialEntity target, boolean copyIfNull) {
		super.userCredentialToEntity(source, target, copyIfNull);
	}

}
