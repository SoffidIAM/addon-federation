// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.service;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.AttributePolicyCondition;

import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.Policy;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;
import com.soffid.iam.addons.federation.common.SamlValidationResults;

import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.SeyconException;
import es.caib.seycon.ng.exception.UnknownUserException;

import com.soffid.iam.addons.federation.model.AttributeConditionEntity;
import com.soffid.iam.addons.federation.model.AttributeEntity;
import com.soffid.iam.addons.federation.model.AttributePolicyEntity;
import com.soffid.iam.addons.federation.model.EntityGroupEntity;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.IdentityProviderEntity;
import com.soffid.iam.model.AuditEntity;
import com.soffid.iam.model.Parameter;
import com.soffid.iam.model.PasswordDomainEntity;
import com.soffid.iam.model.PasswordPolicyEntity;
import com.soffid.iam.model.SystemEntity;
import com.soffid.iam.model.UserDataEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.service.ConfigurationService;
import com.soffid.iam.utils.AutoritzacionsUsuari;
import com.soffid.iam.utils.MailUtils;
import com.soffid.iam.utils.Security;
import com.soffid.iam.addons.federation.model.AttributeEntityDao;
import com.soffid.iam.addons.federation.model.PolicyConditionEntity;
import com.soffid.iam.addons.federation.model.PolicyEntity;
import com.soffid.iam.addons.federation.model.Saml1ArtifactResolutionProfileEntity;
import com.soffid.iam.addons.federation.model.Saml1AttributeQueryProfileEntity;
import com.soffid.iam.addons.federation.model.Saml2ArtifactResolutionProfileEntity;
import com.soffid.iam.addons.federation.model.Saml2AttributeQueryProfileEntity;
import com.soffid.iam.addons.federation.model.Saml2ECPProfileEntity;
import com.soffid.iam.addons.federation.model.Saml2SSOProfileEntity;
import com.soffid.iam.addons.federation.model.SamlProfileEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity;
import com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity;
import com.soffid.iam.addons.federation.service.impl.SAMLServiceInternal;
import com.soffid.iam.api.AttributeVisibilityEnum;
import com.soffid.iam.api.Audit;
import com.soffid.iam.api.Configuration;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.MailDomain;
import com.soffid.iam.api.MetadataScope;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.PolicyCheckResult;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserData;

/**
 * @see es.caib.seycon.ng.servei.FederacioService
 */
public class FederacioServiceImpl 
	extends FederacioServiceBase {

	private static final String EMAIL = "EMAIL"; //$NON-NLS-1$
	private static final String RECOVER_KEY = "RecoverKey"; //$NON-NLS-1$
	private static final String ACTIVATION_KEY = "ActivationKey"; //$NON-NLS-1$

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#create(com.soffid.iam.addons.federation.common.EntityGroup)
	 */
	protected com.soffid.iam.addons.federation.common.EntityGroup handleCreate(com.soffid.iam.addons.federation.common.EntityGroup entityGroup)
			throws java.lang.Exception {
		if (AutoritzacionsUsuari.canCreateAllIdentityFederation()) {
			EntityGroupEntity entity = getEntityGroupEntityDao().entityGroupToEntity(entityGroup);
			getEntityGroupEntityDao().create(entity);
			creaAuditoria("SC_ENTGRP", "C", entityGroup.getName()); //$NON-NLS-1$ //$NON-NLS-2$
			return getEntityGroupEntityDao().toEntityGroup(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToMakeEntityGroup")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#update(com.soffid.iam.addons.federation.common.EntityGroup)
	 */
	protected com.soffid.iam.addons.federation.common.EntityGroup handleUpdate(com.soffid.iam.addons.federation.common.EntityGroup entityGroup)
			throws java.lang.Exception {
		if (AutoritzacionsUsuari.canUpdateAllIdentityFederation()) {
			EntityGroupEntity entity = getEntityGroupEntityDao().entityGroupToEntity(entityGroup);
			getEntityGroupEntityDao().update(entity);
			creaAuditoria("SC_ENTGRP", "U", entityGroup.getName()); //$NON-NLS-1$ //$NON-NLS-2$
			return getEntityGroupEntityDao().toEntityGroup(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToUpdateEntityGroup")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#delete(com.soffid.iam.addons.federation.common.EntityGroup)
	 */
	protected void handleDelete(com.soffid.iam.addons.federation.common.EntityGroup entityGroup) throws java.lang.Exception {
		if (AutoritzacionsUsuari.canDeleteAllIdentityFederation()) {
			EntityGroupEntity entity = getEntityGroupEntityDao().entityGroupToEntity(entityGroup);
			
			if (!entity.getMembers().isEmpty()) {
				throw new SeyconException(Messages.getString("FederacioServiceImpl.DeleteBrancheError")); //$NON-NLS-1$
			}
			
			creaAuditoria("SC_ENTGRP", "D", entityGroup.getName()); //$NON-NLS-1$ //$NON-NLS-2$
			getEntityGroupEntityDao().remove(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToDeleteEntityGroup")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#create(com.soffid.iam.addons.federation.common.FederationMember)
	 */
	protected com.soffid.iam.addons.federation.common.FederationMember handleCreate(com.soffid.iam.addons.federation.common.FederationMember federationMember)
			throws java.lang.Exception {
		if (AutoritzacionsUsuari.canCreateAllIdentityFederation()) {
			FederationMemberEntity entity = getFederationMemberEntityDao().federationMemberToEntity(federationMember);
			getFederationMemberEntityDao().create(entity);
			String desc = federationMember.getPublicId()
					+ (federationMember.getName() != null ? " - " + federationMember.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
			creaAuditoria("SC_FEDERA", "C", desc); //$NON-NLS-1$ //$NON-NLS-2$
			return getFederationMemberEntityDao().toFederationMember(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToMakeFederationMember")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#update(com.soffid.iam.addons.federation.common.FederationMember)
	 */
	protected com.soffid.iam.addons.federation.common.FederationMember handleUpdate(com.soffid.iam.addons.federation.common.FederationMember federationMember)
			throws java.lang.Exception {
		if (AutoritzacionsUsuari.canUpdateAllIdentityFederation())
		{
			// Check allow auto-register
			if (federationMember.isAllowRegister() &&
				(federationMember.getGroupToRegister() == null))
			{
				throw new InternalErrorException(
						com.soffid.iam.addons.federation.service.Messages
								.getString("FederacioServiceImpl.PrimaryGroupError")); //$NON-NLS-1$
			}
			
			FederationMemberEntity entity = getFederationMemberEntityDao().federationMemberToEntity(federationMember);

			// Procesem els relying parties
			if (entity instanceof IdentityProviderEntity) {
				IdentityProviderEntity idp = (IdentityProviderEntity) entity;
				Collection<ServiceProviderVirtualIdentityProviderEntity> sps = idp.getServiceProviderVirtualIdentityProvider();
				// Borramos los antiguos
				List<ServiceProviderVirtualIdentityProviderEntity> oldrps = getServiceProviderVirtualIdentityProviderEntityDao().findByVIP(idp.getId());
				if (oldrps != null) {
					for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = oldrps.iterator(); it.hasNext();) {
						ServiceProviderVirtualIdentityProviderEntity sp = it.next();
						boolean trobat = false;
						for (Iterator<ServiceProviderVirtualIdentityProviderEntity> sit = sps.iterator(); !trobat && sit.hasNext();) {
							ServiceProviderVirtualIdentityProviderEntity s = sit.next();
							if (sp.getId().equals(s.getId())) {
								trobat = true;
							}
						}
						if (!trobat) {
							sp.setServiceProvider(null);
							sp.setVirtualIdentityProvider(null);
							getServiceProviderVirtualIdentityProviderEntityDao().remove(sp); // l'esborrem
						}
					}

				}
				// Creamos los nuevos
				if (sps != null) {
					HashSet<ServiceProviderVirtualIdentityProviderEntity> spsnou = new HashSet<ServiceProviderVirtualIdentityProviderEntity>(
							sps.size());
					for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = sps.iterator(); it.hasNext();) {
						ServiceProviderVirtualIdentityProviderEntity sp = it.next();
						if (sp.getId() == null) {
							getServiceProviderVirtualIdentityProviderEntityDao().create(sp);
						}
						spsnou.add(sp); // nou amb id o existent
					}
					// getServiceProviderVirtualIdentityProviderEntityDao().update(spsnou);
					idp.setServiceProviderVirtualIdentityProvider(spsnou);
				}
				getIdentityProviderEntityDao().update(idp);
				String desc = idp.getPublicId() + (idp.getName() != null ? " - " + idp.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				creaAuditoria("SC_FEDERA", "U", desc); //$NON-NLS-1$ //$NON-NLS-2$
				return getFederationMemberEntityDao().toFederationMember(idp);
			} else if (entity instanceof VirtualIdentityProviderEntity) {
				VirtualIdentityProviderEntity vip = (VirtualIdentityProviderEntity) entity;
				Collection<ServiceProviderVirtualIdentityProviderEntity> sps = vip.getServiceProviderVirtualIdentityProvider();
				// Borramos los antiguos
				List<ServiceProviderVirtualIdentityProviderEntity> oldrps = 
						getServiceProviderVirtualIdentityProviderEntityDao().findByVIP(vip.getId());
				if (oldrps != null) {
					for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = oldrps.iterator(); it.hasNext();) {
						ServiceProviderVirtualIdentityProviderEntity sp = it.next();
						boolean trobat = false;
						for (Iterator<ServiceProviderVirtualIdentityProviderEntity> sit = sps.iterator(); !trobat && sit.hasNext();) {
							ServiceProviderVirtualIdentityProviderEntity s = sit.next();
							if (sp.getId().equals(s.getId())) {
								trobat = true;
							}
						}
						if (!trobat) {
							sp.setServiceProvider(null);
							sp.setVirtualIdentityProvider(null);
							getServiceProviderVirtualIdentityProviderEntityDao().remove(sp); // l'esborrem
						}
					}

				}
				// Creamos los nuevos
				if (sps != null) {
					HashSet<ServiceProviderVirtualIdentityProviderEntity> spsnou = new HashSet<ServiceProviderVirtualIdentityProviderEntity>(
							sps.size());
					for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = sps.iterator(); it.hasNext();) {
						ServiceProviderVirtualIdentityProviderEntity sp = it.next();
						if (sp.getId() == null) {
							getServiceProviderVirtualIdentityProviderEntityDao().create(sp);
						}
						spsnou.add(sp); // nou amb id o existent
					}
					// getServiceProviderVirtualIdentityProviderEntityDao().update(spsnou);
					vip.setServiceProviderVirtualIdentityProvider(spsnou);
				}
				getFederationMemberEntityDao().update(vip);
				String desc = vip.getPublicId() + (vip.getName() != null ? " - " + vip.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				creaAuditoria("SC_FEDERA", "U", desc); //$NON-NLS-1$ //$NON-NLS-2$
				return getFederationMemberEntityDao().toFederationMember(vip);
			} else if (entity instanceof ServiceProviderEntity) {
				ServiceProviderEntity sp = (ServiceProviderEntity) entity;
				getVirtualIdentityProviderEntityDao().update(sp);
				String desc = sp.getPublicId() + (sp.getName() != null ? " - " + sp.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				creaAuditoria("SC_FEDERA", "U", desc); //$NON-NLS-1$ //$NON-NLS-2$
				return getFederationMemberEntityDao().toFederationMember(sp);
			}
			// Per a la resta (SP)
			getVirtualIdentityProviderEntityDao().update(entity);
			creaAuditoria("SC_FEDERA", "U", entity.getName()); //$NON-NLS-1$ //$NON-NLS-2$
			return getFederationMemberEntityDao().toFederationMember(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToUpdateFederationMember")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#delete(com.soffid.iam.addons.federation.common.FederationMember)
	 */
	protected void handleDelete(com.soffid.iam.addons.federation.common.FederationMember federationMember) throws java.lang.Exception {
		if (AutoritzacionsUsuari.canDeleteAllIdentityFederation()) {
			FederationMemberEntity entity = getFederationMemberEntityDao().federationMemberToEntity(federationMember);
			if (entity instanceof IdentityProviderEntity) {
				// IDP
				IdentityProviderEntity idp = (IdentityProviderEntity) entity;
				Collection<SamlProfileEntity> profileCol = idp.getProfiles();
				for(SamlProfileEntity profile : profileCol){
					getSamlProfileEntityDao().remove(profile);
				}
				getIdentityProviderEntityDao().remove(idp);

				String desc = idp.getPublicId() + (idp.getName() != null ? " - " + idp.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				creaAuditoria("SC_FEDERA", "D", desc); //$NON-NLS-1$ //$NON-NLS-2$

			} else if (entity instanceof VirtualIdentityProviderEntity) {
				// VIP
				VirtualIdentityProviderEntity vip = (VirtualIdentityProviderEntity) entity;
				vip.setDefaultIdentityProvider(null);
				// Esborrem els seus relying parties
				List<ServiceProviderVirtualIdentityProviderEntity> oldrps = 
						getServiceProviderVirtualIdentityProviderEntityDao().findByVIP(vip.getId());
				getServiceProviderVirtualIdentityProviderEntityDao().remove(oldrps);
				vip.setServiceProviderVirtualIdentityProvider(null);
				getVirtualIdentityProviderEntityDao().remove(vip);

				String desc = vip.getPublicId() + (vip.getName() != null ? " - " + vip.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				creaAuditoria("SC_FEDERA", "D", desc); //$NON-NLS-1$ //$NON-NLS-2$

			} else if (entity instanceof ServiceProviderEntity) {
				// SP
				ServiceProviderEntity sp = (ServiceProviderEntity) entity;
				// Esborrem la referencia com a relying party
				ArrayList<ServiceProviderVirtualIdentityProviderEntity> oldrps = new ArrayList<ServiceProviderVirtualIdentityProviderEntity>(
						getServiceProviderVirtualIdentityProviderEntityDao().findBySP(sp.getId()));
				getServiceProviderVirtualIdentityProviderEntityDao().remove(oldrps);
				sp.setServiceProviderVirtualIdentityProvider(null);
				getServiceProviderEntityDao().remove(sp);

				String desc = sp.getPublicId() + (sp.getName() != null ? " - " + sp.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				creaAuditoria("SC_FEDERA", "D", desc); //$NON-NLS-1$ //$NON-NLS-2$
			} else
				getFederationMemberEntityDao().remove(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToDeleteFederationMember")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#create(com.soffid.iam.addons.federation.common.SAMLProfile)
	 */
	protected com.soffid.iam.addons.federation.common.SAMLProfile handleCreate(com.soffid.iam.addons.federation.common.SAMLProfile samlProfile)
			throws java.lang.Exception {
		if (AutoritzacionsUsuari.canCreateAllIdentityFederation()) {
			SamlProfileEntity entity = getSamlProfileEntityDao().sAMLProfileToEntity(samlProfile);
			getSamlProfileEntityDao().create(entity);

			String desc = samlProfile.getClasse().toString();
			if (entity.getVirtualIdentityProvider() != null) {
				desc += " (" //$NON-NLS-1$
						+ entity.getVirtualIdentityProvider().getPublicId()
						+ (entity.getVirtualIdentityProvider().getName() != null ? " - " //$NON-NLS-1$
								+ entity.getVirtualIdentityProvider().getName() : "") + ")"; //$NON-NLS-1$ //$NON-NLS-2$
			}
			creaAuditoria("SC_SAMLPRO", "C", desc); //$NON-NLS-1$ //$NON-NLS-2$

			guardaDataModificacioFederacio();

			return getSamlProfileEntityDao().toSAMLProfile(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToMakeProfiles")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#update(com.soffid.iam.addons.federation.common.SAMLProfile)
	 */
	protected com.soffid.iam.addons.federation.common.SAMLProfile handleUpdate(com.soffid.iam.addons.federation.common.SAMLProfile samlProfile)
			throws java.lang.Exception {// throw new Exception ("ups");
		if (AutoritzacionsUsuari.canUpdateAllIdentityFederation()) {
			SamlProfileEntity entity = getSamlProfileEntityDao().sAMLProfileToEntity(samlProfile);
			// Atenció amb l'herència.. si ja existeix i es canvia el tipus s'ha
			// de fer un casting (!!)

			if (SamlProfileEnumeration.SAML2_ECP.equals(samlProfile.getClasse())) {
				getSaml2ECPProfileEntityDao().update((Saml2ECPProfileEntity) entity);
			} else if (SamlProfileEnumeration.SAML2_AR.equals(samlProfile.getClasse())) {
				getSaml2ArtifactResolutionProfileEntityDao().update((Saml2ArtifactResolutionProfileEntity) entity);
			} else if (SamlProfileEnumeration.SAML1_AR.equals(samlProfile.getClasse())) {
				getSaml1ArtifactResolutionProfileEntityDao().update((Saml1ArtifactResolutionProfileEntity) entity);
			} else if (SamlProfileEnumeration.SAML2_SSO.equals(samlProfile.getClasse())) {
				getSaml2SSOProfileEntityDao().update((Saml2SSOProfileEntity) entity);
			} else if (SamlProfileEnumeration.SAML2_AQ.equals(samlProfile.getClasse())) {
				getSaml2AttributeQueryProfileEntityDao().update((Saml2AttributeQueryProfileEntity) entity);
			} else if (SamlProfileEnumeration.SAML1_AQ.equals(samlProfile.getClasse())) {
				getSaml1AttributeQueryProfileEntityDao().update((Saml1AttributeQueryProfileEntity) entity);
			} else {
				getSamlProfileEntityDao().update(entity);
			}

			String desc = samlProfile.getClasse().toString();
			if (entity.getVirtualIdentityProvider() != null) {
				desc += " (" //$NON-NLS-1$
						+ entity.getVirtualIdentityProvider().getPublicId()
						+ (entity.getVirtualIdentityProvider().getName() != null ? " - " //$NON-NLS-1$
								+ entity.getVirtualIdentityProvider().getName() : "") + ")"; //$NON-NLS-1$ //$NON-NLS-2$
			}
			creaAuditoria("SC_SAMLPRO", "U", desc); //$NON-NLS-1$ //$NON-NLS-2$

			guardaDataModificacioFederacio();

			return getSamlProfileEntityDao().toSAMLProfile(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToUpdateProfiles")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#delete(com.soffid.iam.addons.federation.common.SAMLProfile)
	 */
	protected void handleDelete(com.soffid.iam.addons.federation.common.SAMLProfile samlProfile) throws java.lang.Exception {
		if (AutoritzacionsUsuari.canDeleteAllIdentityFederation()) {
			SamlProfileEntity entity = getSamlProfileEntityDao().sAMLProfileToEntity(samlProfile);
			getSamlProfileEntityDao().remove(entity);

			String desc = samlProfile.getClasse().toString();
			if (entity.getVirtualIdentityProvider() != null) {
				desc += " (" //$NON-NLS-1$
						+ entity.getVirtualIdentityProvider().getPublicId()
						+ (entity.getVirtualIdentityProvider().getName() != null ? " - " //$NON-NLS-1$
								+ entity.getVirtualIdentityProvider().getName() : "") + ")"; //$NON-NLS-1$ //$NON-NLS-2$
			}
			creaAuditoria("SC_SAMLPRO", "D", desc); //$NON-NLS-1$ //$NON-NLS-2$

			guardaDataModificacioFederacio();

		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToDeleteProfiles")); //$NON-NLS-1$
	}

	private void getAllCondicionsFilles(Collection<PolicyConditionEntity> condicionsFilles, ArrayList allCondition) {

		if (condicionsFilles != null) {
			for (Iterator it = condicionsFilles.iterator(); it.hasNext();) {
				PolicyConditionEntity item = (PolicyConditionEntity) it.next();
				allCondition.add(item);

				Collection tchs = item.getCondition();
				// I els seus fills
				if (tchs != null && tchs.size() != 0)
					getAllCondicionsFilles(tchs, allCondition);
			}
		}
	}

	private void getAllCondicionsAtributFilles(Collection<PolicyConditionEntity> collection, ArrayList allCondition,
			AttributeConditionEntity condicioPare) {

		if (collection != null) {
			for (Iterator it = collection.iterator(); it.hasNext();) {
				AttributeConditionEntity item = (AttributeConditionEntity) it.next();
				// heretem el valor da allowed de la condició pare
				if (condicioPare != null)
					item.setAllow(condicioPare.isAllow());
				allCondition.add(item);

				Collection tchs = item.getCondition();
				// I els seus fills
				if (tchs != null && tchs.size() != 0)
					getAllCondicionsAtributFilles(tchs, allCondition, condicioPare);
			}
		}
	}

	private void guardaDataModificacioPolitiques() throws InternalErrorException {
		ConfigurationService cs = getConfigurationService();
		Configuration c = cs.findParameterByNameAndNetworkName("saml.policy.lastchange", null); //$NON-NLS-1$
		long aramateix = Calendar.getInstance().getTimeInMillis();
		if (c == null) {
			c = new Configuration("saml.policy.lastchange", "" + aramateix); //$NON-NLS-1$ //$NON-NLS-2$
			cs.create(c);
		} else {
			c.setValue("" + aramateix); //$NON-NLS-1$
			cs.update(c);
		}
	}

	private void guardaDataModificacioFederacio() throws InternalErrorException {
		ConfigurationService cs = getConfigurationService();
		Configuration c = cs.findParameterByNameAndNetworkName("saml.federation.lastchange", null); //$NON-NLS-1$
		long aramateix = Calendar.getInstance().getTimeInMillis();
		if (c == null) {
			c = new Configuration("saml.federation.lastchange", "" + aramateix); //$NON-NLS-1$ //$NON-NLS-2$
			cs.create(c);
		} else {
			c.setValue("" + aramateix); //$NON-NLS-1$
			cs.update(c);
		}
	}

	private void creaAuditoria(String taula, String accio, String federacio) {
		Principal principal = Security.getPrincipal();
		// Corregim accés sense principal (donar d'alta usuaris)
		String codiUser = principal != null ? principal.getName() : "SEYCON"; //$NON-NLS-1$
		Audit auditoria = new Audit();
		auditoria.setAction(accio);
		auditoria.setObject(taula);
		auditoria.setAuthor(codiUser);
		if (federacio != null && federacio.length() > 100) {
			federacio = federacio.substring(0, 100);
		}
		auditoria.setIdentityFederation(federacio);

		auditoria.setCalendar(Calendar.getInstance());

		AuditEntity auditoriaEntity = getAuditEntityDao().auditToEntity(auditoria);
		getAuditEntityDao().create(auditoriaEntity);
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#create(com.soffid.iam.addons.federation.common.Policy)
	 */
	protected com.soffid.iam.addons.federation.common.Policy handleCreate(com.soffid.iam.addons.federation.common.Policy policy) throws java.lang.Exception {
		if (AutoritzacionsUsuari.canCreateAllIdentityFederation()) {
			PolicyEntity entity = getPolicyEntityDao().policyToEntity(policy);
			// Es nova, hem de crear les policyCondition i les
			// attributeCondition
			if (entity.getCondition() != null) {
				// Creem la policyCondition (i les seues condicions filles)
				PolicyConditionEntity cond = entity.getCondition();
				ArrayList<PolicyConditionEntity> allCondition = new ArrayList();
				allCondition.add(cond);
				// Obtenim les seues filles
				getAllCondicionsFilles(cond.getCondition(), allCondition);
				// I les crrem
				getPolicyConditionEntityDao().create(allCondition);
				// La principal serà la primera

				entity.setCondition(allCondition.iterator().next());
			}

			// creem l'entitat (es fa referència a attributePolicy)
			getPolicyEntityDao().create(entity); // PolicyEntity

			// AttributePolicyEntity [0..*]
			if (entity.getAttributePolicy() != null && entity.getAttributePolicy().size() != 0) {
				Collection<AttributePolicyEntity> attp = entity.getAttributePolicy();
				HashSet<AttributePolicyEntity> attributePolicyCreades = new HashSet<AttributePolicyEntity>();
				// Hem de crear les condicions filles:
				// AttributePolicyEntity que conté:
				// - Atribut (ja existent)
				// - AttributeCondition (nou - s'ha de crear)
				for (Iterator<AttributePolicyEntity> it = attp.iterator(); it.hasNext();) {
					AttributePolicyEntity ape = (AttributePolicyEntity) it.next();
					// Indiquem el policy en el AttributePolicy
					ape.setPolicy(entity);

					// Atribut:
					// ja el tenim carregat??
					AttributeEntity att = ape.getAttribute();
					// Condició:
					AttributeConditionEntity atc = ape.getAttributeCondition();

					if (atc != null) {
						// creem les condicions filles (si existeixen)
						ArrayList<AttributeConditionEntity> allCondition = new ArrayList<AttributeConditionEntity>();
						allCondition.add(atc);
						// Obtenim les seues filles
						getAllCondicionsAtributFilles(atc.getCondition(), allCondition, atc);
						// I les creem (totes les condicions anidades)
						getAttributeConditionEntityDao().create(allCondition);

						// Ara establim aquestes condicions
						// la ppal serà la primera
						ape.setAttributeCondition(allCondition.iterator().next());
					}

					// ara la creem la AttributePolicy
					getAttributePolicyEntityDao().create(ape);
					attributePolicyCreades.add(ape);
				}
				entity.setAttributePolicy(attributePolicyCreades);
			}
			guardaDataModificacioPolitiques();
			creaAuditoria("SC_POLICY", "C", policy.getName()); //$NON-NLS-1$ //$NON-NLS-2$

			return getPolicyEntityDao().toPolicy(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToMakePolitics")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#update(com.soffid.iam.addons.federation.common.Policy)
	 */
	protected com.soffid.iam.addons.federation.common.Policy handleUpdate(com.soffid.iam.addons.federation.common.Policy policy) throws java.lang.Exception {
		if (AutoritzacionsUsuari.canUpdateAllIdentityFederation()) {
			// TODO: fer-lo bé...
			Policy clon = clonaPolicy(policy, true);
			delete(policy);
			Policy nova = create(clon);
			guardaDataModificacioPolitiques();
			creaAuditoria("SC_POLICY", "U", policy.getName()); //$NON-NLS-1$ //$NON-NLS-2$

			return nova;
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToUpdatePolitics")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#delete(com.soffid.iam.addons.federation.common.Policy)
	 */
	protected void handleDelete(com.soffid.iam.addons.federation.common.Policy policy) throws java.lang.Exception {
		if (AutoritzacionsUsuari.canDeleteAllIdentityFederation()) {
			PolicyEntity entity = getPolicyEntityDao().policyToEntity(policy);

			// AttributePolicyEntity [0..*]
			if (entity.getAttributePolicy() != null && entity.getAttributePolicy().size() != 0) {
				Collection attp = entity.getAttributePolicy();
				// Hem de crear les condicions filles:
				// AttributePolicyEntity que conté:
				// - Atribut (ja existent)
				// - AttributeCondition (nou - s'ha de crear)
				for (Iterator it = attp.iterator(); it.hasNext();) {
					AttributePolicyEntity ape = (AttributePolicyEntity) it.next();

					// Atribut:
					// ja el tenim carregat??
					AttributeEntity att = ape.getAttribute();
					// Condició:
					AttributeConditionEntity atc = ape.getAttributeCondition();
					ArrayList<AttributeConditionEntity> allConditionAtt = new ArrayList<AttributeConditionEntity>();

					if (atc != null) {
						// creem les condicions filles (si existeixen)

						allConditionAtt.add(atc);
						// Obtenim les seues filles (heretant el valor de
						// allowed del pare)
						getAllCondicionsAtributFilles(atc.getCondition(), allConditionAtt, atc);

					}
					ape.setAttribute(null);
					ape.setPolicy(null);
					ape.setAttributeCondition(null);

					// getAttributePolicyEntityDao().update(ape);

					// ara esborrem la AttributePolicy
					getAttributePolicyEntityDao().remove(ape);
					// I les seves condicions d'atribut
					getAttributeConditionEntityDao().remove(allConditionAtt);
				}

			}

			ArrayList<PolicyConditionEntity> allCondition = new ArrayList();

			// Es nova, hem de crear les policyCondition i les
			// attributeCondition
			if (entity.getCondition() != null) {
				// Creem la policyCondition (i les seues condicions filles)
				PolicyConditionEntity cond = entity.getCondition();

				allCondition.add(cond);
				// Obtenim les seues filles
				getAllCondicionsFilles(cond.getCondition(), allCondition);
			}

			// Referencies a politiques i politiques d'atributs
			// (atribut + attributeCondition)
			entity.setCondition(null);
			entity.setAttributePolicy(null); // esborrem referencia
			// I les seves condicions
			getPolicyConditionEntityDao().remove(allCondition);
			// I finalment esborrem la politica
			getPolicyEntityDao().remove(entity);

			guardaDataModificacioPolitiques(); // guardem data

			creaAuditoria("SC_POLICY", "D", policy.getName()); //$NON-NLS-1$ //$NON-NLS-2$

		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.UserNotAuthorizedToDeletePolitics")); //$NON-NLS-1$
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#create(com.soffid.iam.addons.federation.common.Attribute)
	 */
	protected com.soffid.iam.addons.federation.common.Attribute handleCreate(com.soffid.iam.addons.federation.common.Attribute attribute) throws java.lang.Exception {
		AttributeEntityDao dao = getAttributeEntityDao();
		AttributeEntity entity = dao.newAttributeEntity();
		dao.attributeToEntity(attribute, entity, true);
		dao.create(entity);
		return dao.toAttribute(entity);
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#update(com.soffid.iam.addons.federation.common.Attribute)
	 */
	protected com.soffid.iam.addons.federation.common.Attribute handleUpdate(com.soffid.iam.addons.federation.common.Attribute attribute) throws java.lang.Exception {
		AttributeEntityDao dao = getAttributeEntityDao();
		AttributeEntity entity = dao.load(attribute.getId());
		dao.attributeToEntity(attribute, entity, true);
		dao.create(entity);
		return dao.toAttribute(entity);
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#delete(com.soffid.iam.addons.federation.common.Attribute)
	 */
	protected void handleDelete(com.soffid.iam.addons.federation.common.Attribute attribute) throws java.lang.Exception {
		AttributeEntityDao dao = getAttributeEntityDao();
		AttributeEntity entity = dao.load(attribute.getId());
		dao.remove(entity);
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#findEntityGroupByNom(java.lang.String)
	 */
	protected java.util.Collection<EntityGroupMember> handleFindEntityGroupByNom(java.lang.String nom) throws java.lang.Exception {
		Collection entityGroups = null;
		LinkedList<EntityGroupMember> resultat = new LinkedList();
		if (!"-ARREL-".equals(nom)) { //$NON-NLS-1$
			entityGroups = getEntityGroupEntityDao().findByName(nom);
		} else {
			EntityGroupMember arrel = new EntityGroupMember("ARREL"); //$NON-NLS-1$
			arrel.setDescripcio("Federation"); //$NON-NLS-1$
			resultat.add(arrel);
			return resultat;
		}

		if (entityGroups != null) {
			// Obtenim els seus filla dels EG
			for (Iterator<EntityGroupEntity> it = entityGroups.iterator(); it.hasNext();) {
				EntityGroupEntity ega = it.next();
				EntityGroup eg = getEntityGroupEntityDao().toEntityGroup(ega);
				EntityGroupMember egm = new EntityGroupMember(ega.getName(), EG_EG, eg, null);
				// Afegim el EG
				resultat.add(egm);
			}
			return resultat;
		}
		return new LinkedList();
	}

	/**
	 * @see es.caib.seycon.ng.servei.FederacioService#findPolicies(com.soffid.iam.addons.federation.common.FederationMember)
	 */
	/*protected java.util.Collection handleFindPolicies(com.soffid.iam.addons.federation.common.FederationMember federationMember)
			throws java.lang.Exception {
		if (federationMember != null && federationMember.getId() != null && "I".equals(federationMember.getClasse())) {
			Collection policies = getPolicyEntityDao().findByidentiyProviderId(federationMember.getId());
			getPolicyEntityDao().toPolicyCollection(policies);
			return policies;
		}
		return new ArrayList();
	}*/

	final static String EG_IDP = "IDP"; //$NON-NLS-1$
	final static String EG_SP = "SP"; //$NON-NLS-1$
	final static String EG_IDP_ROOT = "IDP_ROOT"; //$NON-NLS-1$
	final static String EG_SP_ROOT = "SP_ROOT"; //$NON-NLS-1$
	final static String EG_EG = "EG"; //$NON-NLS-1$
	final static String EG_VIP = "VIP"; //$NON-NLS-1$

	@Override
	protected Collection<EntityGroupMember> handleFindChildren(EntityGroupMember groupMember) throws Exception {
		Collection<EntityGroupMember> resultat = new LinkedList();

		// Hem de cercar els fills segons el tipus
		// EntityGroup
		if ("ARREL".equals(groupMember.getTipus())) { //$NON-NLS-1$
			return handleFindEntityGroupByNom("%"); //$NON-NLS-1$
		} else if (EG_EG.equals(groupMember.getTipus())) {
			if (groupMember.getEntityGrupPare() != null) {

				EntityGroup pare = groupMember.getEntityGrupPare();
				// Afegim fills ficticis per agrupar IdP i SP

				resultat.add(new EntityGroupMember("Identity Providers", EG_IDP_ROOT, pare, null)); //$NON-NLS-1$
				resultat.add(new EntityGroupMember("Service Providers", EG_SP_ROOT, pare, null)); //$NON-NLS-1$

			}
		} else if (EG_IDP_ROOT.equals(groupMember.getTipus())) {
			// Cerquem els seus IDPs fills
			EntityGroup pare = groupMember.getEntityGrupPare();
			Collection idp = getIdentityProviderEntityDao().findIDPByEntityGroupId(pare.getId());

			for (Iterator<FederationMemberEntity> it = idp.iterator(); it.hasNext();) {
				FederationMemberEntity fme = it.next();
				FederationMember fm = getFederationMemberEntityDao().toFederationMember(fme);
				String desc = fm.getPublicId() + (fm.getName() != null ? " - " + fm.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				resultat.add(new EntityGroupMember(desc, EG_IDP, pare, fm));
			}
		} else if (EG_SP_ROOT.equals(groupMember.getTipus())) {
			EntityGroup pare = groupMember.getEntityGrupPare();

			Collection sp = getServiceProviderEntityDao().findSPByEntityGroupId(pare.getId());

			// Obtenim els membres per id del grup pare
			// Afegim els fills classificats
			for (Iterator<FederationMemberEntity> it = sp.iterator(); it.hasNext();) {
				FederationMemberEntity fme = it.next();
				FederationMember fm = getFederationMemberEntityDao().toFederationMember(fme);
				String desc = fm.getPublicId() + (fm.getName() != null ? " - " + fm.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				resultat.add(new EntityGroupMember(desc, EG_SP, pare, fm));
			}
		} else if (EG_IDP.equals(groupMember.getTipus())) {
			// IDENTITY PROVIDER

			EntityGroup pare = groupMember.getEntityGrupPare();
			FederationMember fm = groupMember.getFederationMember();

			// Obtenim els membres per id del grup pare
			IdentityProviderEntity idp = (IdentityProviderEntity) getIdentityProviderEntityDao().load(fm.getId());

			Collection vip = idp.getVirtualIdentityProvider();

			for (Iterator<FederationMemberEntity> it = vip.iterator(); it.hasNext();) {
				FederationMemberEntity fme = it.next();
				FederationMember fmi = getFederationMemberEntityDao().toFederationMember(fme);
				String desc = fmi.getPublicId() + (fmi.getName() != null ? " - " + fmi.getName() : ""); //$NON-NLS-1$ //$NON-NLS-2$
				resultat.add(new EntityGroupMember(desc, EG_VIP, pare, fmi));
			}

		}

		return resultat;
	}

	@Override
	protected EntityGroupMember handleCreate(EntityGroupMember entityGroupMember) throws Exception {
		// Aqui es poden crear EntityGroup i FederationMember
		// ho mirem en el tipus
		if (EG_EG.equals(entityGroupMember.getTipus())) {
			EntityGroup eg = entityGroupMember.getEntityGrupPare();
			// Obtenim el name de la descripció
			eg.setName(entityGroupMember.getDescripcio());
			eg = this.create(eg);
			entityGroupMember.setEntityGrupPare(eg);
			guardaDataModificacioFederacio();
			return entityGroupMember;
		} else if (EG_IDP.equals(entityGroupMember.getTipus()) || EG_VIP.equals(entityGroupMember.getTipus())
				|| EG_SP.equals(entityGroupMember.getTipus())) {
			// Federation member, establim el seu publicid
			// el seu EntityGroup pare ha d'existir ja..
			FederationMember fm = entityGroupMember.getFederationMember();
			// fm.setPublicId(entityGroupMember.getDescripcio());
			fm = this.create(fm);
			entityGroupMember.setFederationMember(fm);
			guardaDataModificacioFederacio();
			return entityGroupMember;
		}
		throw new SeyconException(Messages.getString("FederacioServiceImpl.NonSupported")); //$NON-NLS-1$
	}

	@Override
	protected EntityGroupMember handleUpdate(EntityGroupMember entityGroupMember) throws Exception {
		// Ho fem mirant el tipus
		if ("EG".equals(entityGroupMember.getTipus())) { //$NON-NLS-1$
			EntityGroup eg = entityGroupMember.getEntityGrupPare();
			if (eg != null) {
				// Posem l'atribut que es sutitueix al UI
				eg.setName(entityGroupMember.getDescripcio());
				eg = this.update(eg);
				guardaDataModificacioFederacio();
				entityGroupMember.setEntityGrupPare(eg);
				return entityGroupMember;
			} else
				throw new SeyconException(Messages.getString("FederacioServiceImpl.EntityGroupNotFounded")); //$NON-NLS-1$
		} else if ("SP".equals(entityGroupMember.getTipus()) || "IDP".equals(entityGroupMember.getTipus()) //$NON-NLS-1$ //$NON-NLS-2$
				|| "VIP".equals(entityGroupMember.getTipus())) { //$NON-NLS-1$
			FederationMember fm = entityGroupMember.getFederationMember();
			if (fm != null) {
				// Posem l'atribut que es sutitueix al UI
				// fm.setPublicId(entityGroupMember.getDescripcio());
				fm = this.update(fm);
				guardaDataModificacioFederacio();
				entityGroupMember.setFederationMember(fm);
				return entityGroupMember;
			} else
				throw new SeyconException(Messages.getString("FederacioServiceImpl.FederationMemberNotFounded")); //$NON-NLS-1$
		}
		return entityGroupMember;
	}

	@Override
	protected void handleDelete(EntityGroupMember entityGroupMember) throws Exception {

		// Branques artificials... que no existeixen a la bbdd
		if ("SP_ROOT".equals(entityGroupMember.getTipus()) || "IDP_ROOT".equals(entityGroupMember.getTipus())) //$NON-NLS-1$ //$NON-NLS-2$
			return;

		// hem d'esborrar segons el tipus de membre (FM o EG)
		EntityGroup eg = entityGroupMember.getEntityGrupPare();
		if (eg != null) {
			// FM
			if ("IDP".equals(entityGroupMember.getTipus()) || "SP".equals(entityGroupMember.getTipus()) //$NON-NLS-1$ //$NON-NLS-2$
					|| "VIP".equals(entityGroupMember.getTipus())) {  //$NON-NLS-1$
				FederationMember fm = entityGroupMember.getFederationMember();
				if (fm != null) {
					this.delete(fm);
					guardaDataModificacioFederacio();
					return;
				} else
					throw new SeyconException(Messages.getString("FederacioServiceImpl.FederationMemberNotFounded")); //$NON-NLS-1$
			} else if ("EG".equals(entityGroupMember.getTipus())) { //$NON-NLS-1$
				// EG
				this.delete(eg);
				guardaDataModificacioFederacio();
				return;
			}

		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.EntityGroupNotFounded")); //$NON-NLS-1$
	}

	@Override
	protected Collection<SAMLProfile> handleFindProfilesByFederationMember(FederationMember federationMember) throws Exception {
		if (federationMember != null && federationMember.getId() != null) {
			Collection<SamlProfileEntity> profiles = getSamlProfileEntityDao().findByVIPId(federationMember.getId());
			return getSamlProfileEntityDao().toSAMLProfileList(profiles);
		}
		return null;

	}

	@Override
	protected Collection<Attribute> handleFindAtributs(String name, String shortName, String oid) throws Exception {
		// Fem la cerca d'atributs
		Collection<AttributeEntity>  res = getAttributeEntityDao().findByNameShortNameOid(name, shortName, oid);
		return getAttributeEntityDao().toAttributeList(res);
	}

	@Override
	protected PolicyCondition handleCreate(PolicyCondition policyCondition) throws Exception {
		if (AutoritzacionsUsuari.canCreateAllIdentityFederation()) {
			PolicyConditionEntity entity = getPolicyConditionEntityDao().policyConditionToEntity(policyCondition);
			getPolicyConditionEntityDao().create(entity);
			guardaDataModificacioPolitiques();
			return getPolicyConditionEntityDao().toPolicyCondition(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToMakePolicyCondition")); //$NON-NLS-1$

	}

	@Override
	protected PolicyCondition handleUpdate(PolicyCondition policyCondition) throws Exception {
		if (AutoritzacionsUsuari.canUpdateAllIdentityFederation()) {
			PolicyConditionEntity entity = getPolicyConditionEntityDao().policyConditionToEntity(policyCondition);
			getPolicyConditionEntityDao().update(entity);
			guardaDataModificacioPolitiques();
			return getPolicyConditionEntityDao().toPolicyCondition(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToUpdatePolicyCondition")); //$NON-NLS-1$
	}

	@Override
	protected void handleDelete(PolicyCondition policyCondition) throws Exception {
		if (AutoritzacionsUsuari.canDeleteAllIdentityFederation()) {
			PolicyConditionEntity entity = getPolicyConditionEntityDao().policyConditionToEntity(policyCondition);
			getPolicyConditionEntityDao().remove(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToDeletePolicyCondition")); //$NON-NLS-1$
	}

	@Override
	protected AttributePolicyCondition handleCreate(AttributePolicyCondition attributeCondition) throws Exception {
		if (AutoritzacionsUsuari.canCreateAllIdentityFederation()) {
			AttributeConditionEntity entity = getAttributeConditionEntityDao().attributePolicyConditionToEntity(attributeCondition);
			getAttributeConditionEntityDao().create(entity);
			return getAttributeConditionEntityDao().toAttributePolicyCondition(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToMakeAttributeCondition")); //$NON-NLS-1$

	}

	@Override
	protected AttributePolicyCondition handleUpdate(AttributePolicyCondition attributeCondition) throws Exception {
		if (AutoritzacionsUsuari.canUpdateAllIdentityFederation()) {
			AttributeConditionEntity entity = getAttributeConditionEntityDao().attributePolicyConditionToEntity(attributeCondition);
			getAttributeConditionEntityDao().update(entity);
			return getAttributeConditionEntityDao().toAttributePolicyCondition(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToUpdateAttributeCondition")); //$NON-NLS-1$
	}

	@Override
	protected void handleDelete(AttributePolicyCondition attributeCondition) throws Exception {
		if (AutoritzacionsUsuari.canDeleteAllIdentityFederation()) {
			AttributeConditionEntity entity = getAttributeConditionEntityDao().attributePolicyConditionToEntity(attributeCondition);
			getAttributeConditionEntityDao().remove(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToDeleteAttributeCondition")); //$NON-NLS-1$
	}

	@Override
	protected AttributePolicy handleCreate(AttributePolicy attributePolicy) throws Exception {
		if (AutoritzacionsUsuari.canCreateAllIdentityFederation()) {
			AttributePolicyEntity entity = getAttributePolicyEntityDao().attributePolicyToEntity(attributePolicy);
			getAttributePolicyEntityDao().create(entity);
			guardaDataModificacioPolitiques();
			return getAttributePolicyEntityDao().toAttributePolicy(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToMakeAttributePolicy")); //$NON-NLS-1$
	}

	@Override
	protected AttributePolicy handleUpdate(AttributePolicy attributePolicy) throws Exception {
		if (AutoritzacionsUsuari.canUpdateAllIdentityFederation()) {
			AttributePolicyEntity entity = getAttributePolicyEntityDao().attributePolicyToEntity(attributePolicy);
			getAttributePolicyEntityDao().update(entity);
			guardaDataModificacioPolitiques();
			return getAttributePolicyEntityDao().toAttributePolicy(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToUpdateAttributePolicy")); //$NON-NLS-1$
	}

	@Override
	protected void handleDelete(AttributePolicy attributePolicy) throws Exception {
		if (AutoritzacionsUsuari.canDeleteAllIdentityFederation()) {
			AttributePolicyEntity entity = getAttributePolicyEntityDao().attributePolicyToEntity(attributePolicy);
			guardaDataModificacioPolitiques();
			getAttributePolicyEntityDao().remove(entity);
		} else
			throw new SeyconException(Messages.getString("FederacioServiceImpl.NotAuthorizedToDeleteAttributePolicy")); //$NON-NLS-1$

	}

	@Override
	protected Collection<AttributePolicyCondition>  handleFindAttributePolicy(Policy policy) throws Exception {
		if (policy != null && policy.getId() != null) {
			List<AttributeConditionEntity> attPolCE = getAttributeConditionEntityDao().findAttributeConditionByAttributePolicyId(
					policy.getId());
			return getAttributeConditionEntityDao().toAttributePolicyConditionList(attPolCE);

		}
		return new ArrayList();
	}

	@Override
	protected Collection<PolicyCondition>  handleFindPolicyCondition(Policy policy) throws Exception {
		if (policy != null && policy.getId() != null) {
			List<PolicyConditionEntity> policyCE = getPolicyConditionEntityDao().findByPolicyId(policy.getId());
			return getPolicyConditionEntityDao().toPolicyConditionList(policyCE);
		}
		return new LinkedList();
	}

	@Override
	protected Collection<AttributePolicyCondition> handleFindAttributeCondition(AttributePolicy attributePolicy) throws Exception {
		if (attributePolicy != null && attributePolicy.getId() != null) {
			List<AttributeConditionEntity> attributeCE = getAttributeConditionEntityDao().findAttributeConditionByPolicyId(
					attributePolicy.getId());
			return getAttributeConditionEntityDao().toAttributePolicyConditionList(attributeCE);
		}
		return new ArrayList();
	}

	private Policy clonaPolicy(Policy original, boolean comNova) {
		// copiem la base
		Policy nova = new Policy(original);
		nova.setId(null); // com a nou
		if (original.getCondition() != null) {
			// el clonem
			PolicyCondition clonPC = clonaPC(original.getCondition(), comNova);
			nova.setCondition(clonPC);
		}

		if (original.getAttributePolicy() != null) {
			Collection attPolicy = original.getAttributePolicy();
			ArrayList clonAttributePolicy = new ArrayList(attPolicy.size());
			for (Iterator<AttributePolicy> it = attPolicy.iterator(); it.hasNext();) {
				AttributePolicy attPolOriginal = it.next();
				// Creem el clon
				AttributePolicy clonAttPol = new AttributePolicy(attPolOriginal);
				if (attPolOriginal.getAttribute() != null)
					clonAttPol.setAttribute(new Attribute(attPolOriginal.getAttribute()));
				if (comNova)
					clonAttPol.setId(null);// nou
				// clonem els AttributePolicyCondition de l'original
				AttributePolicyCondition clonAPC = clonaAC(attPolOriginal.getAttributePolicyCondition(), comNova);
				clonAttPol.setAttributePolicyCondition(clonAPC);
				clonAttributePolicy.add(clonAttPol);
			}
			nova.setAttributePolicy(clonAttributePolicy);
		}

		return nova;
	}

	private PolicyCondition clonaPC(PolicyCondition original, boolean comNova) {
		PolicyCondition pc = new PolicyCondition(original);
		if (original.getAttribute() != null)
			pc.setAttribute(new Attribute(original.getAttribute()));
		if (comNova)
			pc.setId(null); // nou
		if (original.getChildrenCondition() != null) {
			Collection children = original.getChildrenCondition();
			Collection childrenNous = new ArrayList();
			if (children != null)
				for (Iterator<PolicyCondition> it = children.iterator(); it.hasNext();) {
					PolicyCondition f = it.next();
					childrenNous.add(clonaPC(f, comNova));
				}
			pc.setChildrenCondition(childrenNous);
		}
		return pc;
	}

	private AttributePolicyCondition clonaAC(AttributePolicyCondition original, boolean comNova) {
		AttributePolicyCondition pc = new AttributePolicyCondition(original);
		if (original.getAttribute() != null)
			pc.setAttribute(new Attribute(original.getAttribute()));
		if (comNova)
			pc.setId(null);// nou
		if (original.getChildrenCondition() != null) {
			Collection children = original.getChildrenCondition();
			Collection childrenNous = new ArrayList();
			if (children != null)
				for (Iterator<AttributePolicyCondition> it = children.iterator(); it.hasNext();) {
					AttributePolicyCondition f = it.next();
					childrenNous.add(clonaAC(f, comNova));
				}
			pc.setChildrenCondition(childrenNous);
		}
		return pc;
	}

	@Override
	protected Collection<FederationMember> handleFindFederationMemberByEntityGroupAndPublicIdAndTipus(String entityGroupName,
			String publicId, String tipus) throws Exception {
		String selectI = "select fm from com.soffid.iam.addons.federation.model.IdentityProviderEntity fm where (:tipusFM='I') and (:entityGroupName is null or fm.entityGroup.name like :entityGroupName) and (:publicId is null or fm.publicId like :publicId)"; //$NON-NLS-1$
		String selectV = "select fm from com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity fm where (:tipusFM='V') and (:entityGroupName is null or fm.entityGroup.name like :entityGroupName) and (:publicId is null or fm.publicId like :publicId)"; //$NON-NLS-1$
		String selectS = "select fm from com.soffid.iam.addons.federation.model.ServiceProviderEntity fm where (:tipusFM='S') and (:entityGroupName is null or fm.entityGroup.name like :entityGroupName) and (:publicId is null or fm.publicId like :publicId)"; //$NON-NLS-1$
		String select = "I".equals(tipus) ? selectI : "S".equals(tipus) ? selectS : selectV; //$NON-NLS-1$ //$NON-NLS-2$
		Collection fms = getFederationMemberEntityDao().query(select,
				new Parameter[] {
			new Parameter ("tipusFM", tipus), //$NON-NLS-1$
			new Parameter ("entityGroupName", entityGroupName), //$NON-NLS-1$
			new Parameter ("publicId", publicId), //$NON-NLS-1$
		});
		List<FederationMember> fmvos = getFederationMemberEntityDao().toFederationMemberList(fms);
		if (fms != null)
			for (Iterator<FederationMember> it = fmvos.iterator(); it.hasNext();) {
				FederationMember fm = it.next();
				fm.setClasse("I".equals(fm.getClasse()) ? "Identity Provider" : "S".equals(fm.getClasse()) ? "Service Provider" : "V" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
						.equals(fm.getClasse()) ? "Virtual Identity Provider" : "Federation Member"); //$NON-NLS-1$ //$NON-NLS-2$
			}
		return fmvos;
	}

	@Override
	protected String[] handleGenerateKeys() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		SecureRandom r = SecureRandom.getInstance("SHA1PRNG"); //$NON-NLS-1$
		keyGen.initialize(1024, r);
		KeyPair pair = keyGen.genKeyPair();

		PublicKey publickey = pair.getPublic();
		PrivateKey privateKey = pair.getPrivate();

		
		StringWriter swpr = new StringWriter();
		PemWriter pwpr = new PemWriter(swpr);
		pwpr.writeObject(new JcaMiscPEMGenerator(privateKey));
		pwpr.close();

		StringWriter swpu = new StringWriter();
		PemWriter pwpu = new PemWriter(swpu);
		pwpu.writeObject(new JcaMiscPEMGenerator(publickey));
		pwpu.close();
		
		Object cert = generateSelfSignedCert (pair);
		StringWriter swcert = new StringWriter();
		PemWriter pwcert = new PemWriter(swcert);
		pwcert.writeObject(new JcaMiscPEMGenerator(cert));
		pwcert.close();
		

		return new String[] { swpu.toString(), swpr.toString(), swcert.toString() };
	}

    private X509V3CertificateGenerator getX509Generator(String name) {

        long now = System.currentTimeMillis() - 1000 * 60 * 10; // 10 minutos
        long l = now + 1000L * 60L * 60L * 24L * 365L * 5L; // 5 años
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        generator.setIssuerDN(new X509Name(name));
        generator.setNotAfter(new Date(l));
        generator.setNotBefore(new Date(now));
        generator.setSerialNumber(BigInteger.valueOf(now));
        generator.setSignatureAlgorithm("sha1WithRSAEncryption");
        return generator;
    }

	private Object generateSelfSignedCert(KeyPair pair) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
		String name = "Autosigned-"+System.currentTimeMillis();
		String dn = "CN="+name+",OU=Federation services,O=SOFFID";
        X509V3CertificateGenerator generator = getX509Generator(dn);
        Vector<ASN1ObjectIdentifier> tags = new Vector<ASN1ObjectIdentifier>();
        Vector<String> values = new Vector<String>();
        generator.setSubjectDN(new X509Name(dn));
        generator.setPublicKey(pair.getPublic());
        generator.setNotBefore(new Date());
        generator.setSignatureAlgorithm("SHA256WithRSA");
        Calendar c = Calendar.getInstance();
        c.add(Calendar.YEAR, 10);
        generator.setNotAfter(c.getTime());
        return generator.generate(pair.getPrivate(), "BC");
	}

	@Override
	protected Collection<Policy> handleFindPolicies() throws Exception {
		List<PolicyEntity> policies = getPolicyEntityDao().loadAll();
		return getPolicyEntityDao().toPolicyList(policies);
	}

	@Override
	protected String handleGeneratePKCS10(FederationMember federationMember) throws Exception {
		FederationMember fm = federationMember;
		if (fm.getPrivateKey() == null || "".equals(fm.getPrivateKey().trim()) || fm.getPublicKey() == null //$NON-NLS-1$
				|| "".equals(fm.getPublicKey().trim())) { //$NON-NLS-1$
			throw new Exception(Messages.getString("FederacioServiceImpl.MakePKCS10Message"));  //$NON-NLS-1$
		}

		java.security.PrivateKey _privateKey = null;
		java.security.PublicKey _publicKey = null;

		try {
			java.security.Security.addProvider(new BouncyCastleProvider());
		} catch (Throwable th) {
			
		}

		PEMParser pemParser = new PEMParser(new StringReader(fm.getPrivateKey()));
		Object object = pemParser.readObject();
		if (object instanceof KeyPair) {
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		    KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
			_privateKey = kp.getPrivate();
		} else if (object instanceof PrivateKey) {
			_privateKey = (PrivateKey) object;
		}
		pemParser.close();

		pemParser = new PEMParser(new StringReader(fm.getPublicKey()));
		object = pemParser.readObject();
		if (object instanceof KeyPair) {
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		    KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
		    _publicKey = kp.getPublic();
		} else if (object instanceof PrivateKey) {
			_publicKey = (PublicKey) object;
		}
		pemParser.close();

		org.bouncycastle.jce.PKCS10CertificationRequest pkcs10 = new org.bouncycastle.jce.PKCS10CertificationRequest("SHA1withRSA", //$NON-NLS-1$
				new javax.security.auth.x500.X500Principal("CN=" + fm.getPublicId() + ",OU=" + fm.getEntityGroup().getName()), //$NON-NLS-1$ //$NON-NLS-2$
				_publicKey, null, _privateKey, "SunRsaSign"); //$NON-NLS-1$
		return new String(es.caib.seycon.util.Base64.encodeBytes(pkcs10.getEncoded()));
	}

	@Override
	protected String handleGetPolicyDescriptionForAccount(String account,
			String dispatcher) throws Exception {
		if (dispatcher == null)
			dispatcher = getPasswordService().getDefaultDispatcher();
		return getPasswordService().getPolicyDescription(account, dispatcher);
	}

	@Override
	protected String handleGetPolicyDescriptionForUserType(String userType,
			String dispatcher) throws Exception {
		if (dispatcher == null)
			dispatcher = getPasswordService().getDefaultDispatcher();
		SystemEntity dispatcherEntity = getSystemEntityDao().findByName(dispatcher);
		if (dispatcherEntity == null)
			return null;
		
		PasswordPolicyEntity policy = getPasswordPolicyEntityDao().
				findByPasswordDomainAndUserType(
						dispatcherEntity.getPasswordDomain().getName(), userType);
		if (policy == null)
			return null;
		return getInternalPasswordService().getPolicyDescription(policy);
	}

	@Override
	protected PolicyCheckResult handleCheckPolicy(String userType, String dispatcher, 
			Password password) throws Exception {
		if (dispatcher == null)
			dispatcher = getPasswordService().getDefaultDispatcher();
		SystemEntity dispatcherEntity = getSystemEntityDao().findByName(dispatcher);
		if (dispatcherEntity == null)
			return null;
		
		PasswordPolicyEntity policy = getPasswordPolicyEntityDao()
				.findByPasswordDomainAndUserType(
						dispatcherEntity.getPasswordDomain().getName(), userType);
		return getInternalPasswordService().checkPolicy(policy, password);
	}

	@Override
	protected void handleSendActivationEmail(java.lang.String user, java.lang.String mailHost, 
			java.lang.String from, 
			java.lang.String activationUrl, 
			java.lang.String organizationName) throws Exception {
		User usuari = getUserService().findUserByUserName(user);
		if (user == null)
			throw new UnknownUserException (user);
		
		String to;
		if (usuari.getShortName() != null && usuari.getMailDomain() != null)
			to = usuari.getShortName()+ "@" + usuari.getMailDomain(); //$NON-NLS-1$
		else
		{
			UserData dada = getUserService().findDataByUserAndCode(user, EMAIL);
			if (dada == null || dada.getValue() == null || dada.getValue().isEmpty())
				throw new InternalErrorException (String.format(com.soffid.iam.addons.federation.service.Messages.getString("FederacioServiceImpl.UnableGetMailError"), user)); //$NON-NLS-1$
			to = dada.getValue();
		}
		
		StringBuffer key = new StringBuffer();
		SecureRandom sr = new SecureRandom();
		for (int i = 0; i < 76; i++)
		{
			int n = sr.nextInt(62);
			if ( n < 10)
				key.append ( (char) ('0' + n));
			else if (n < 36)
				key.append ( (char) ('a' + n - 10));
			else
				key.append ( (char) ('A' + n - 36));
		}
		key.append(usuari.getId());
		
		Collection<DataType> list = getAdditionalDataService().findDataTypesByScopeAndName(MetadataScope.USER, ACTIVATION_KEY);
		DataType tda;
		if (list == null || list.isEmpty())
		{
			tda = new DataType ();
			tda.setCode(ACTIVATION_KEY);
			tda.setOrder(-100L);
			tda.setType(TypeEnumeration.STRING_TYPE);
			tda.setOperatorVisibility(AttributeVisibilityEnum.HIDDEN);
			tda.setAdminVisibility(AttributeVisibilityEnum.EDITABLE);
			tda.setUserVisibility(AttributeVisibilityEnum.HIDDEN);
			getAdditionalDataService().create (tda);
		} else {
			tda = list.iterator().next();
		}
		
		UserData dadaUser = new UserData ();
		dadaUser.setAttribute(tda.getCode());
		dadaUser.setUser(usuari.getUserName());
		dadaUser.setValue(key.toString());
		getAdditionalDataService().create(dadaUser);
		
		StringBuffer url = new StringBuffer(activationUrl);
		if (url.indexOf("?") >= 0) //$NON-NLS-1$
			url.append("&"); //$NON-NLS-1$
		else
			url.append("?"); //$NON-NLS-1$
		url.append ("key=").append(key); //$NON-NLS-1$

		String subject = String.format (com.soffid.iam.addons.federation.service.Messages.getString("FederacioServiceImpl.ActivationMailMsg")); //$NON-NLS-1$
		StringBuffer message = new StringBuffer();
		message.append ("<body><html><p>" ); //$NON-NLS-1$
		message.append ( String.format (com.soffid.iam.addons.federation.service.Messages
				.getString("FederacioServiceImpl.RecentlyRegisteredAccountMsg"), 
				usuari.getUserName(), organizationName)); //$NON-NLS-1$
		message.append ( String.format("</p><p><a href='%s'>", url.toString())); //$NON-NLS-1$
		message.append ( com.soffid.iam.addons.federation.service.Messages.getString("FederacioServiceImpl.ActivateButtonMsg") ); //$NON-NLS-1$
		message.append ( "</p></html></body>"); //$NON-NLS-1$
		
		MailUtils.sendHtmlMail(mailHost, to, from, subject, message.toString());
	}

	@Override
	protected User handleVerifyActivationEmail(String key) throws Exception {
		List<UserDataEntity> dades = getUserDataEntityDao().findByTypeAndValue(ACTIVATION_KEY, key);
		for (UserDataEntity dada: dades)
		{
			UserData du = getUserDataEntityDao().toUserData(dada);
			getAdditionalDataService().delete(du);
			User usuari = getUserService().findUserByUserName(du.getUser());
			if (!usuari.getActive().booleanValue())
			{
				usuari.setActive(Boolean.TRUE);
				getUserService().update(usuari);
			}
			return usuari;
		}
		return null;
	}

	@Override
	protected void handleSendRecoverEmail(String email, 
			java.lang.String mailHost, 
			java.lang.String from, 
			java.lang.String activationUrl, 
			java.lang.String organizationName) throws Exception 
	{
		int atSign = email.indexOf("@"); //$NON-NLS-1$
		if (atSign < 0)
			throw new InternalErrorException(String.format (com.soffid.iam.addons.federation.service.Messages.getString("FederacioServiceImpl.InvalidMailAddressMsg"), email)); //$NON-NLS-1$
		
		String leftSide = email.substring(0, atSign);
		String rightSide = email.substring(atSign+1);
		User usuari = null;
		Collection<User> usuaris = getUserService().findUserByCriteria("%" // codi  //$NON-NLS-1$
				,null // nom
				, null // primerLlinatge
				,leftSide // nomCurt
				,null  // dataCreacio
				,null // usuariCreacio
				,"S" // actiu //$NON-NLS-1$
				, null // segonLlinatge
				, null // multiSessio
				, null // comentari
				, null // tipusUser
				, null // servidorPerfil
				, null // servidorHome
				, null // servidorCorreu
				, null //  codiGrupPrimari
				, null // dni
				, rightSide // dominiCorreu
				, null // grupSecundari
				, false );  // restringeixCerca);
		
		
		if (! usuaris.isEmpty())
			usuari = usuaris.iterator().next();
		else
		{
			List<UserDataEntity> dades = getUserDataEntityDao().findByTypeAndValue(EMAIL, email);
			if (!dades.isEmpty())
			{
				UserDataEntity dada = dades.iterator().next();
				usuari = getUserService().findUserByUserId(dada.getUser().getId());
			
			}
		}

		if (usuari == null)
		{
			throw new UnknownUserException(email);
		}
		
		StringBuffer key = new StringBuffer();
		SecureRandom sr = new SecureRandom();
		for (int i = 0; i < 76; i++)
		{
			int n = sr.nextInt(62);
			if ( n < 10)
				key.append ( (char) ('0' + n));
			else if (n < 36)
				key.append ( (char) ('a' + n - 10));
			else
				key.append ( (char) ('A' + n - 36));
		}
		key.append(usuari.getId());
		
		Collection<DataType> list = getAdditionalDataService().findDataTypesByScopeAndName(MetadataScope.USER, RECOVER_KEY);
		DataType tda;
		if (list == null || list.isEmpty())
		{
			tda = new DataType ();
			tda.setCode(RECOVER_KEY);
			tda.setOrder(-101L);
			tda.setType(TypeEnumeration.STRING_TYPE);
			tda.setOperatorVisibility(AttributeVisibilityEnum.HIDDEN);
			tda.setAdminVisibility(AttributeVisibilityEnum.EDITABLE);
			tda.setUserVisibility(AttributeVisibilityEnum.HIDDEN);
			getAdditionalDataService().create (tda);
		}
		else
		{
			tda = list.iterator().next();
		}
		
		UserData dadaUser = getUserService().findDataByUserAndCode(usuari.getUserName(), tda.getCode());
		if (dadaUser != null)
		{
			getAdditionalDataService().delete(dadaUser);
		}
		dadaUser = new UserData ();
		dadaUser.setAttribute(tda.getCode());
		dadaUser.setUser(usuari.getUserName());
		dadaUser.setValue(key.toString());
		getAdditionalDataService().create(dadaUser);
		
		StringBuffer url = new StringBuffer(activationUrl);
		if (url.indexOf("?") >= 0) //$NON-NLS-1$
			url.append("&"); //$NON-NLS-1$
		else
			url.append("?"); //$NON-NLS-1$
		url.append ("key=").append(key); //$NON-NLS-1$
			
		String subject = String.format (com.soffid.iam.addons.federation.service.Messages
				.getString("FederacioServiceImpl.AccountRecoverMsg")); //$NON-NLS-1$
		StringBuffer message = new StringBuffer();
		message.append ("<body><html><p>" ); //$NON-NLS-1$
		message.append ( String.format (com.soffid.iam.addons.federation.service.Messages
				.getString("FederacioServiceImpl.RequestedRecoverPasswordMsg"), 
				usuari.getUserName(), organizationName)); //$NON-NLS-1$
		message.append ( String.format("</p><p><a href='%s'>", url.toString())); //$NON-NLS-1$
		message.append ( com.soffid.iam.addons.federation.service.Messages.getString("FederacioServiceImpl.RecoverButtonMsg") ); //$NON-NLS-1$
		message.append ( "</p></html></body>"); //$NON-NLS-1$
		
		MailUtils.sendHtmlMail(mailHost, email, from, subject, message.toString());
	}

	@Override
	protected User handleVerifyRecoverEmail(String key) throws Exception {
		List<UserDataEntity> dades = getUserDataEntityDao().findByTypeAndValue(RECOVER_KEY, key);
		for (UserDataEntity dada: dades)
		{
			UserData du = getUserDataEntityDao().toUserData(dada);
			User usuari = getUserService().findUserByUserName(du.getUser());
			if (usuari.getActive().booleanValue())
			{
				getAdditionalDataService().delete(du);
				return usuari;
			}
		}
		return null;
		
	}

	@Override
	protected User handleRegisterUser(String dispatcher, User usuari, Map additionalData,
			Password password) throws Exception {
		
		usuari = registerUser(usuari, additionalData, false);
		
		UserEntity usuariEntity = getUserEntityDao().load(usuari.getId());
		PasswordDomainEntity dce = getPasswordDomainEntityDao().findBySystem(dispatcher);
		
		getInternalPasswordService().storeAndForwardPassword(usuariEntity, dce, password, false);
		return usuari;
	}

	private User registerUser(User usuari, Map additionalData, boolean reuseEmail)
			throws InternalErrorException {
		final Map<String, String> additionalData2 = (Map<String, String>) additionalData; 
		String email = additionalData2.get(EMAIL);
		if (email != null)
		{
			int separator = email.indexOf("@"); //$NON-NLS-1$
			if (separator < 0 || email.contains(" ") || email.contains(">") || email.contains("<")) //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				throw new InternalErrorException (com.soffid.iam.addons.federation.service.Messages.getString("FederacioServiceImpl.WrongMailFormatMsg")); //$NON-NLS-1$
			String domain = email.substring(separator + 1);
			MailDomain domini = getMailListsService().findMailDomainByName(domain);
			if (domini != null)
				throw new InternalErrorException (String.format(com.soffid.iam.addons.federation.service.Messages.getString("FederacioServiceImpl.AddressDomainErrorMsg"), domain)); //$NON-NLS-1$
			
			List<UserDataEntity> usuaris = getUserDataEntityDao().findByTypeAndValue(EMAIL, email); 
			if (usuaris.size() == 1 && reuseEmail)
			{
				UserDataEntity dada = usuaris.get(0);
				UserEntity usuariEntity = dada.getUser();
				User usuari2 = getUserEntityDao().toUser(usuariEntity);
				usuari2.setFirstName(usuari.getFirstName());
				usuari2.setLastName(usuari.getLastName());
				usuari2.setMiddleName(usuari.getMiddleName());
				getUserService().update(usuari2);
				return usuari2;
			}
			if (! usuaris.isEmpty())
			{
				throw new InternalErrorException (String.format(com.soffid.iam.addons.federation.service.Messages.getString("FederacioServiceImpl.AlreadyRegisteredMailMsg"), email)); //$NON-NLS-1$
			}
		}
		
		usuari = getUserService().create(usuari);
		for ( String key: additionalData2.keySet())
		{
    		Collection<DataType> l = getAdditionalDataService().findDataTypesByScopeAndName(MetadataScope.USER, key);
    		if (l == null || l.isEmpty())
    		{
    			DataType tda = new DataType();
    			tda.setCode(key);
    			tda.setOrder(0L);
    			tda.setType(TypeEnumeration.STRING_TYPE);
    			tda.setScope(MetadataScope.USER);
    			tda.setOperatorVisibility(AttributeVisibilityEnum.EDITABLE);
    			tda.setAdminVisibility(AttributeVisibilityEnum.EDITABLE);
    			tda.setUserVisibility(AttributeVisibilityEnum.HIDDEN);

    			tda = getAdditionalDataService().create(tda);
    		}

    		UserData dada = new UserData();
    		dada.setAttribute(key);
    		dada.setUser(usuari.getUserName());
    		dada.setValue( additionalData2.get(key));
			getAdditionalDataService().create(dada);
		}
		return usuari;
	}

	@Override
	protected User handleRegisterOpenidUser(String account,
			String dispatcher, User usuari, Map additionalData) throws Exception {
		long n = System.currentTimeMillis() % 1000000L;
		String codi = (String) additionalData.get(EMAIL);
		do
		{
			User u2 = getUserService().findUserByUserName(codi);
			if (u2 == null)
			{
				// Creates the user
				usuari.setUserName(codi);
				usuari = registerUser(usuari, additionalData, true);
				// Creates the openid account
				
				SystemEntity de = getSystemEntityDao().findByName(dispatcher);
				com.soffid.iam.api.System dvo = getSystemEntityDao().toSystem(de);
				getAccountService().createAccount(usuari, dvo, account);
				
				break;
			}
			n++;
			codi = usuari.getUserType();
			codi = codi + n;
		} while (true);
		return usuari;
	}

	
	@Override
	protected String [] handleParsePkcs12(byte[] pkcs12, String password) throws Exception {
		KeyStore store  = KeyStore.getInstance("PKCS12");
		store.load (new ByteArrayInputStream (pkcs12), password.toCharArray());
		
		Key privateKey;
		PublicKey publicKey;
		String certificateChain;
		
		for ( Enumeration<String> e = store.aliases(); e.hasMoreElements(); )
		{
			String alias = e.nextElement();
			Key key = store.getKey(alias, password.toCharArray());
			if (key != null)
			{
				privateKey = key;
				Certificate[]  certChain=  store.getCertificateChain(alias);
				Certificate cert = store.getCertificate(alias);
				publicKey = cert.getPublicKey();

				StringWriter swpr = new StringWriter();
				PEMWriter pwpr = new PEMWriter(swpr);
				pwpr.writeObject(privateKey);
				pwpr.close();

				StringWriter swpu = new StringWriter();
				PEMWriter pwpu = new PEMWriter(swpu);
				pwpu.writeObject(publicKey);
				pwpu.close();

				StringWriter swcc = new StringWriter();
				PEMWriter pwcc = new PEMWriter(swcc);
				for (Certificate c: certChain)
					pwcc.writeObject(c);
				pwcc.close();
				
				return new String [] { swpr.toString(), swpu.toString(), swcc.toString()};
			}
		}
		return null;
	}


	SAMLServiceInternal delegate;
	
	SAMLServiceInternal getDelegate () throws Exception
	{
		if (delegate == null)
		{
			delegate = new SAMLServiceInternal();
			delegate.setConfigurationService(getConfigurationService());
			delegate.setFederationMemberEntityDao(getFederationMemberEntityDao());
			delegate.setSamlRequestEntityDao( getSamlRequestEntityDao());
			delegate.setAccountService(getAccountService());
			delegate.setDispatcherService(getDispatcherService());
			delegate.setUserDomainService(getUserDomainService());
			delegate.setUserService(getUserService());
			delegate.setSessionService ( getSessionService() );
			delegate.setPasswordService(getPasswordService());
		}
		return delegate;
	}

	

	@Override
	protected SamlValidationResults handleAuthenticate(String serviceProviderName, String protocol,
			Map<String, String> response, boolean autoProvision) throws Exception {
		return getDelegate().authenticate ( serviceProviderName, protocol, response, autoProvision);
	}

	@Override
	protected SamlRequest handleGenerateSamlRequest(String serviceProvider, String identityProvider,
			String userName,
			long sessionSeconds) throws Exception {
		if (userName != null && !userName.trim().isEmpty())
		{
			for (FederationMemberEntity fm: getIdentityProviderEntityDao().findFMByPublicId(identityProvider))
			{
				String pattern = fm.getDomainExpression();
				if (pattern != null && !pattern.trim().isEmpty())
				{
					Matcher m = Pattern.compile("^"+pattern+"$").matcher(userName);
					if ( m.matches() && m.group(1) != null)
						userName = m.group(1);
				}
			}
		}
		return getDelegate().generateSamlRequest (serviceProvider, identityProvider, userName, sessionSeconds);
	}

	@Override
	protected SamlValidationResults handleValidateSessionCookie(String sessionCookie) throws Exception {
		return getDelegate().validateSessionCookie(sessionCookie);
	}

	@Override
	protected String handleSearchIdpForUser(String userName) throws Exception {
		for (FederationMemberEntity fm: getFederationMemberEntityDao().loadAll())
		{
			if (fm instanceof IdentityProviderEntity)
			{
				String pattern = fm.getDomainExpression();
				if (pattern != null && !pattern.trim().isEmpty())
				{
					if ( Pattern.matches("^"+pattern+"$", userName))
						return ((IdentityProviderEntity) fm).getPublicId();
				}
			}
		}
		return null;
	}

	@Override
	protected SamlValidationResults handleAuthenticate(String serviceProvider, String identityProvider, 
			String user, String password, long sessionSeconds)
			throws Exception {
		return getDelegate().authenticate(serviceProvider, identityProvider, user, password, sessionSeconds);
	}

	@Override
	protected SamlRequest handleGenerateSamlLogoutRequest(String serviceProvider, String identityProvider,
			String subject, boolean force, boolean backChannel) throws Exception {
		return  getDelegate().generateSamlLogout(serviceProvider, identityProvider, subject, force, backChannel);
	}

}
