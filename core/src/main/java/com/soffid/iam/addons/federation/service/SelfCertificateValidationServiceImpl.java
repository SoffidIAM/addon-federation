package com.soffid.iam.addons.federation.service;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.naming.ldap.LdapName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.RootCertificate;
import com.soffid.iam.addons.federation.common.SelfCertificate;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.RootCertificateEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.api.User;
import com.soffid.iam.interp.Evaluator;
import com.soffid.iam.service.CertificateValidationModule;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class SelfCertificateValidationServiceImpl extends
		SelfCertificateValidationServiceBase
		implements CertificateValidationModule {
	Log log = LogFactory.getLog(getClass());
	
	public SelfCertificateValidationServiceImpl() {
	}

	@Override
	protected com.soffid.iam.api.Account handleGetCertificateAccount(List<X509Certificate> certs)
			throws Exception {
		return null;
	}

	private boolean validate (UserCredentialEntity cert)
	{
		if (cert == null || cert.getType() != UserCredentialType.CERT)
			return false;
		Date now = new Date ();
		if (now.after(cert.getExpirationDate()))
			return false;
		if (now.before(cert.getCreated()))
			return false;
		UserCredentialEntity certEntity = getUserCredentialEntityDao().load(cert.getId());
		if (certEntity.getRoot() == null)
			return false;
		RootCertificateEntity root = certEntity.getRoot();
		if (root.isObsolete())
			return false;
		
		if (root.isExternal())
			return true;
		
		Calendar c = Calendar.getInstance();
		c.setTime(root.getExpirationDate());
		c.add(Calendar.MONTH, root.getUserCertificateMonths());
		if (now.after(c.getTime()))
			return false;
		
		return true;
	}
	
	@Override
	protected User handleGetCertificateUser(List<X509Certificate> certs)
			throws Exception {
		final X509Certificate cert = certs.get(0);
		String pk = Base64.encodeBytes(cert.getPublicKey().getEncoded(), Base64.DONT_BREAK_LINES);
		for (UserCredentialEntity cred: getUserCredentialEntityDao().findByPublicKey(pk)) {
			if (validate(cred))
			{
				return getUserService().findUserByUserId(cred.getUserId());
			}
		}
		for (RootCertificateEntity ac: getRootCertificateEntityDao().loadAll()) {
			if (ac.isExternal()) {
				X509Certificate cacert = getRootCertificateEntityDao().toRootCertificate(ac).getCertificate();
				if (cert.getIssuerX500Principal().equals(cacert.getSubjectX500Principal()))
				{
					try {
						cert.verify(cacert.getPublicKey());
						User user = getCertificateUser(ac, cert);
						if (user != null)
							return user;
					} catch (CertificateException e) {}
					
				}
			}
		}
		return null;
	}

	private User getCertificateUser(RootCertificateEntity ac, X509Certificate cert) throws InternalErrorException, IOException, Exception {
		if (ac.getGuessUserScript() != null && !ac.getGuessUserScript().trim().isEmpty())
		{
			Map<String, Object> newNs = new HashMap<>();
			newNs.put("certificate", cert);
			LdapName subject = new LdapName(cert.getSubjectX500Principal().getName());
			newNs.put("subject", subject);
			
			Object result = Evaluator.instance().evaluate(ac.getGuessUserScript(), 
					newNs , "Certificate parser for "+ac.getOrganizationName());
			if (result != null) {
				User u =getUserService().findUserByUserName(result.toString());
				if (u == null)
					log.warn("Cannot find user "+result.toString());
				return u;
			}
		}
		return null;
	}

	@Override
	protected Collection<X509Certificate> handleGetRootCertificateList()
			throws Exception {
		LinkedList<X509Certificate> certs = new LinkedList<X509Certificate>();
		for (RootCertificate cert: getSelfCertificateService().getRootCertificates())
		{
			if (! cert.isObsolete())
				certs.add(cert.getCertificate());
		}
		return certs;
	}

	@Override
	protected boolean handleValidateCertificate(List<X509Certificate> certs)
			throws Exception {
 		final X509Certificate userCert = certs.get(0);
		String pk = Base64.encodeBytes(userCert.getPublicKey().getEncoded(), Base64.DONT_BREAK_LINES);
		for (UserCredentialEntity cred: getUserCredentialEntityDao().findByPublicKey(pk)) {
			if (validate(cred)) {
				cred.setLastUse(new Date());
				getUserCredentialEntityDao().update(cred);
				return true;
			}
		}
		
		for (RootCertificateEntity ac: getRootCertificateEntityDao().loadAll()) {
			if (ac.isExternal()) {
				X509Certificate cacert = getRootCertificateEntityDao().toRootCertificate(ac).getCertificate();
				if (userCert.getIssuerX500Principal().equals(cacert.getSubjectX500Principal()))
				{
					try {
						userCert.verify(cacert.getPublicKey());
						userCert.checkValidity();
						User u = getCertificateUser(ac, userCert);
						if (u != null) {
							UserCredentialEntity cred = getUserCredentialEntityDao().newUserCredentialEntity();
							cred.setCertificate(Base64.encodeBytes(userCert.getEncoded(), Base64.DONT_BREAK_LINES));
							cred.setCreated(new Date());
							cred.setDescription(userCert.getSubjectDN().getName());
							cred.setExpirationDate(userCert.getNotAfter());
							cred.setKey(pk);
							cred.setLastUse(new Date());
							cred.setRoot(ac);
							cred.setSerialNumber(userCert.getSerialNumber().toString());
							cred.setType(UserCredentialType.CERT);
							cred.setUserId(u.getId());
							getUserCredentialEntityDao().create(cred);
							return true;
						}
					} catch (CertificateException e) {} // Not valid
				}
			}
		}
		return false;
	}

}
