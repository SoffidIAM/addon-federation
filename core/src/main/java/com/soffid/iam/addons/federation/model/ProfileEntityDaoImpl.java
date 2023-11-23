// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;

/**
 * @see com.soffid.iam.addons.federation.model.SamlProfileEntity
 */
public class ProfileEntityDaoImpl extends com.soffid.iam.addons.federation.model.ProfileEntityDaoBase {
	/**
	 * @see com.soffid.iam.addons.federation.model.SamlProfileEntityDao#toSAMLProfile(com.soffid.iam.addons.federation.model.SamlProfileEntity,
	 *      com.soffid.iam.addons.federation.common.SAMLProfile)
	 */
	public void toSAMLProfile(com.soffid.iam.addons.federation.model.ProfileEntity source, com.soffid.iam.addons.federation.common.SAMLProfile target) {
		// @todo verify behavior of toSAMLProfile
		// en principi estan tots els atributs
		super.toSAMLProfile(source, target);

		if ( source instanceof SamlProfileEntity)
		{
			SamlProfileEntity entity = (SamlProfileEntity) source;
			// Les antigues booleanes
			target.setSignResponses(SAMLRequirementEnumeration.fromLong(entity.getSignResponses()));
			target.setSignAssertions(SAMLRequirementEnumeration.fromLong(entity.getSignAssertions()));
			target.setSignRequests(SAMLRequirementEnumeration.fromLong(entity.getSignRequests()));
		}

		// Discriminem segons la sub-classe
		if (source instanceof Saml2ECPProfileEntity) {
			// ECP
			target.setClasse(SamlProfileEnumeration.SAML2_ECP);
			Saml2ECPProfileEntity saml2ecp = (Saml2ECPProfileEntity) source;
			// heretats del pare
			target.setOutboundArtifactType(saml2ecp.getOutboundArtifactType());
			target.setAssertionLifetime(saml2ecp.getAssertionLifetime());
			target.setAssertionProxyCount(saml2ecp.getAssertionProxyCount());
			Long ea = saml2ecp.getEncryptAssertions();
			target.setEncryptAssertions(SAMLRequirementEnumeration.fromLong(ea != null ? ea : SAMLRequirementEnumeration.CONDITIONAL
					.getValue()));
			Long eni = saml2ecp.getEncryptNameIds();
			target.setEncryptNameIds(SAMLRequirementEnumeration.fromLong(eni != null ? eni : SAMLRequirementEnumeration.NEVER
					.getValue()));
			// propis
			target.setIncludeAttributeStatement(saml2ecp.isIncludeAttributeStatement());
			target.setLocalityAddress(saml2ecp.getLocalityAddress());
			target.setLocalityDNSName(saml2ecp.getLocalityDNSName());

		} else if (source instanceof Saml2ArtifactResolutionProfileEntity) {
			// SAML2_AR

			target.setClasse(SamlProfileEnumeration.SAML2_AR);
			Saml2ArtifactResolutionProfileEntity saml2ar = (Saml2ArtifactResolutionProfileEntity) source;
			Long ea = saml2ar.getEncryptAssertions();
			target.setEncryptAssertions(SAMLRequirementEnumeration.fromLong(ea != null ? ea : SAMLRequirementEnumeration.CONDITIONAL
					.getValue()));
			Long eni = saml2ar.getEncryptNameIds();
			target.setEncryptNameIds(SAMLRequirementEnumeration.fromLong(eni != null ? eni : SAMLRequirementEnumeration.NEVER
					.getValue()));
		} else if (source instanceof Saml1ArtifactResolutionProfileEntity) {
			// SAML1_AR

			target.setClasse(SamlProfileEnumeration.SAML1_AR);
		} else if (source instanceof Saml2SSOProfileEntity) {
			target.setClasse(SamlProfileEnumeration.SAML2_SSO);
			// heretats
			Saml2SSOProfileEntity entity = (Saml2SSOProfileEntity) source;
			target.setOutboundArtifactType(entity.getOutboundArtifactType());
			target.setAssertionLifetime(entity.getAssertionLifetime());
			target.setAssertionProxyCount(entity.getAssertionProxyCount());
			Long ea = entity.getEncryptAssertions();
			target.setEncryptAssertions(SAMLRequirementEnumeration.fromLong(ea != null ? ea : SAMLRequirementEnumeration.CONDITIONAL
					.getValue()));
			Long eni = entity.getEncryptNameIds();
			target.setEncryptNameIds(SAMLRequirementEnumeration.fromLong(eni != null ? eni : SAMLRequirementEnumeration.NEVER
					.getValue()));
			// propis
			target.setMaximumSPSessionLifetime(entity.getMaximumSPSessionLifetime());
			target.setIncludeAttributeStatement(entity.isIncludeAttributeStatement());
		} else if (source instanceof Saml2AttributeQueryProfileEntity) {
			target.setClasse(SamlProfileEnumeration.SAML2_AQ);
			// heretats
			Saml2AttributeQueryProfileEntity entity = (Saml2AttributeQueryProfileEntity) source;
			target.setOutboundArtifactType(entity.getOutboundArtifactType());
			target.setAssertionLifetime(entity.getAssertionLifetime());
			// propis
			target.setAssertionProxyCount(entity.getAssertionProxyCount());
			Long ea = entity.getEncryptAssertions();
			target.setEncryptAssertions(SAMLRequirementEnumeration.fromLong(ea != null ? ea : SAMLRequirementEnumeration.CONDITIONAL
					.getValue()));
			Long eni = entity.getEncryptNameIds();
			target.setEncryptNameIds(SAMLRequirementEnumeration.fromLong(eni != null ? eni : SAMLRequirementEnumeration.NEVER
					.getValue()));
		} else if (source instanceof Saml1AttributeQueryProfileEntity) {
			// SAML1_AQ
			target.setClasse(SamlProfileEnumeration.SAML1_AQ);
			Saml1AttributeQueryProfileEntity entity = (Saml1AttributeQueryProfileEntity) source;

			target.setOutboundArtifactType(entity.getOutboundArtifactType());
			target.setAssertionLifetime(entity.getAssertionLifetime());
		} else if (source instanceof OpenidProfileEntity) {
			// heretats
			target.setClasse(SamlProfileEnumeration.OPENID);
			OpenidProfileEntity entity = (OpenidProfileEntity) source;
			target.setAuthorizationEndpoint(entity.getAuthorizationEndpoint());
			target.setEnabled(entity.isEnabled());
			target.setTokenEndpoint(entity.getTokenEndpoint());
			target.setRevokeEndpoint(entity.getRevokeEndpoint());
			target.setUserInfoEndpoint(entity.getUserInfoEndpoint());
		} else if (source instanceof RadiusProfileEntity) {
			// heretats
			target.setClasse(SamlProfileEnumeration.RADIUS);
			RadiusProfileEntity entity = (RadiusProfileEntity) source;
			target.setAcctPort(entity.getAcctPort());
			target.setAuthPort(entity.getAuthPort());
			target.setPap(entity.getPap());
			target.setChap(entity.getChap());
			target.setMsChap(entity.getMsChap());
			target.setEnabled(entity.isEnabled());
			target.setSecurePort(entity.getSecurePort());
			target.setFreeRadiusPort(entity.getFreeRadiusPort());
		} else if (source instanceof TacacsProfileEntity) {
			// heretats
			target.setClasse(SamlProfileEnumeration.TACACS_PLUS);
			TacacsProfileEntity entity = (TacacsProfileEntity) source;
			target.setAuthPort(entity.getAuthPort());
			target.setPap(entity.getPap());
			target.setChap(entity.getChap());
			target.setMsChap(entity.getMsChap());
			target.setSsl(entity.getSsl());
			target.setAscii(entity.getAscii());
			target.setEnabled(entity.isEnabled());
		} else if (source instanceof CasProfileEntity) {
			// heretats
			target.setClasse(SamlProfileEnumeration.CAS);
			CasProfileEntity entity = (CasProfileEntity) source;
			target.setEnabled(entity.isEnabled());
		} else if (source instanceof WsfedProfileEntity) {
			// heretats
			target.setClasse(SamlProfileEnumeration.WS_FEDERATION);
			WsfedProfileEntity entity = (WsfedProfileEntity) source;
			target.setEnabled(entity.isEnabled());
		} else if (source instanceof SseProfileEntity) {
			// heretats
			target.setClasse(SamlProfileEnumeration.SSE);
			SseProfileEntity entity = (SseProfileEntity) source;
			target.setEnabled(entity.isEnabled());
		} else if (source instanceof SamlProfileEntity) {
			// En teoria aquesta és abstracta
			target.setClasse(SamlProfileEnumeration.SAML_PRO);
		}

	}

	/**
	 * Retrieves the entity object that is associated with the specified value
	 * object from the object store. If no such entity object exists in the
	 * object store, a new, blank entity is created
	 */
	private com.soffid.iam.addons.federation.model.ProfileEntity loadProfileEntityFromSAMLProfile(
			com.soffid.iam.addons.federation.common.SAMLProfile sAMLProfile) {
		com.soffid.iam.addons.federation.model.ProfileEntity samlProfileEntity = null;
		if (sAMLProfile.getId() != null) {
			samlProfileEntity = this.load(sAMLProfile.getId());
		}
		if (samlProfileEntity == null) {
			if (SamlProfileEnumeration.SAML2_ECP.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newSaml2ECPProfileEntity(); 
			} else if (SamlProfileEnumeration.SAML2_AR.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newSaml2ArtifactResolutionProfileEntity(); 
			} else if (SamlProfileEnumeration.SAML1_AR.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newSaml1ArtifactResolutionProfileEntity(); 
			} else if (SamlProfileEnumeration.SAML2_SSO.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newSaml2SSOProfileEntity(); 
			} else if (SamlProfileEnumeration.SAML2_AQ.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newSaml2AttributeQueryProfileEntity(); 
			} else if (SamlProfileEnumeration.SAML1_AQ.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newSaml1AttributeQueryProfileEntity();
			} else if (SamlProfileEnumeration.SAML1_AQ.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newSaml1AttributeQueryProfileEntity();
			} else if (SamlProfileEnumeration.OPENID.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newOpenidProfileEntity();
			} else if (SamlProfileEnumeration.RADIUS.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newRadiusProfileEntity();
			} else if (SamlProfileEnumeration.TACACS_PLUS.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newTacacsProfileEntity();
			} else if (SamlProfileEnumeration.CAS.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newCasProfileEntity();
			} else if (SamlProfileEnumeration.SSE.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newSseProfileEntity();
			} else if (SamlProfileEnumeration.WS_FEDERATION.equals(sAMLProfile.getClasse())) {
				samlProfileEntity = newWsfedProfileEntity();
			} else {
				samlProfileEntity = newSamlProfileEntity();
			}

		}
		return samlProfileEntity;
	}

	/**
	 * @see com.soffid.iam.addons.federation.model.SamlProfileEntityDao#sAMLProfileToEntity(com.soffid.iam.addons.federation.common.SAMLProfile)
	 */
	public com.soffid.iam.addons.federation.model.ProfileEntity sAMLProfileToEntity(com.soffid.iam.addons.federation.common.SAMLProfile sAMLProfile) {
		// @todo verify behavior of sAMLProfileToEntity
		com.soffid.iam.addons.federation.model.ProfileEntity entity = this.loadProfileEntityFromSAMLProfile(sAMLProfile);
		this.sAMLProfileToEntity(sAMLProfile, entity, true);
		return entity;
	}

	/**
	 * @see com.soffid.iam.addons.federation.model.SamlProfileEntityDao#sAMLProfileToEntity(com.soffid.iam.addons.federation.common.SAMLProfile,
	 *      com.soffid.iam.addons.federation.model.SamlProfileEntity)
	 */
	public void sAMLProfileToEntity(com.soffid.iam.addons.federation.common.SAMLProfile source, com.soffid.iam.addons.federation.model.ProfileEntity target,
			boolean copyIfNull) {
		// @todo verify behavior of sAMLProfileToEntity
		super.sAMLProfileToEntity(source, target, copyIfNull);
		// No conversion for target.classe (can't convert
		// source.getClasse():com.soffid.iam.addons.federation.common.SamlProfileEnumeration to
		// java.lang.String

		// guardem el signresponses,signassertions, signrequests
		if (target instanceof SamlProfileEntity)
		{
			SamlProfileEntity t = (SamlProfileEntity) target;
			if (source.getSignResponses() != null) {
				t.setSignResponses(source.getSignResponses().getValue());
			}
	
			if (source.getSignAssertions() != null) {
				t.setSignAssertions(source.getSignAssertions().getValue());
			}
	
			if (source.getSignRequests() != null) {
				t.setSignRequests(source.getSignRequests().getValue());
			}
		}

		// VirtualIdentityProvider
		if (source.getIdentityProvider() != null) {
			if ( source.getIdentityProvider().getId() != null) {
				FederationMember idp = source.getIdentityProvider();
				VirtualIdentityProviderEntity vip = (VirtualIdentityProviderEntity) getFederationMemberEntityDao()
						.federationMemberToEntity(idp);
				target.setVirtualIdentityProvider(vip);
			} else {
				for (FederationMemberEntity fm:getFederationMemberEntityDao().findFMByEntityGroupAndPublicIdAndTipus("%", 
						source.getIdentityProvider().getPublicId(),
						"V")) 
				{
					target.setVirtualIdentityProvider((VirtualIdentityProviderEntity) fm);
				}
				for (FederationMemberEntity fm:getFederationMemberEntityDao().findFMByEntityGroupAndPublicIdAndTipus("%", 
						source.getIdentityProvider().getPublicId(),
						"I")) 
				{
					target.setVirtualIdentityProvider((VirtualIdentityProviderEntity) fm);
				}
				
			}
		} // else throw new Exception
			// ("No s'ha trobat el identity provider del SAMLProfile");

		// Falten les parts de les subclasses

		if (SamlProfileEnumeration.SAML1_AR.equals(source.getClasse())) {
			// res d'específic
		} else if (SamlProfileEnumeration.SAML2_AR.equals(source.getClasse())) {
			Saml2ArtifactResolutionProfileEntity saml2ar = (Saml2ArtifactResolutionProfileEntity) target;
			SAMLRequirementEnumeration ea = source.getEncryptAssertions();
			// Per defecte CONDITIONAL
			saml2ar.setEncryptAssertions(ea != null ? ea.getValue() : SAMLRequirementEnumeration.CONDITIONAL.getValue());
			SAMLRequirementEnumeration eni = source.getEncryptNameIds();
			// Per defecte NEVER
			saml2ar.setEncryptNameIds(eni != null ? eni.getValue() : SAMLRequirementEnumeration.NEVER.getValue());
			target = saml2ar;
		} else if (SamlProfileEnumeration.SAML1_AQ.equals(source.getClasse())) {
			Saml1AttributeQueryProfileEntity entity = (Saml1AttributeQueryProfileEntity) target;
			entity.setOutboundArtifactType(source.getOutboundArtifactType());
			entity.setAssertionLifetime(source.getAssertionLifetime());

			target = entity;
		} else if (SamlProfileEnumeration.SAML2_AQ.equals(source.getClasse())) {
			// heretats
			Saml2AttributeQueryProfileEntity entity = (Saml2AttributeQueryProfileEntity) target;
			entity.setOutboundArtifactType(source.getOutboundArtifactType());
			entity.setAssertionLifetime(source.getAssertionLifetime());
			// propis
			entity.setAssertionProxyCount(source.getAssertionProxyCount());
			SAMLRequirementEnumeration ea = source.getEncryptAssertions();
			// Per defecte CONDITIONAL
			entity.setEncryptAssertions(ea != null ? ea.getValue() : SAMLRequirementEnumeration.CONDITIONAL.getValue());
			SAMLRequirementEnumeration eni = source.getEncryptNameIds();
			// Per defecte NEVER
			entity.setEncryptNameIds(eni != null ? eni.getValue() : SAMLRequirementEnumeration.NEVER.getValue());
			target = entity;
		} else if (SamlProfileEnumeration.SAML2_ECP.equals(source.getClasse())) {
			Saml2ECPProfileEntity saml2ecp = (Saml2ECPProfileEntity) target;
			// heretats del pare
			saml2ecp.setOutboundArtifactType(source.getOutboundArtifactType());
			saml2ecp.setAssertionLifetime(source.getAssertionLifetime());
			saml2ecp.setAssertionProxyCount(source.getAssertionProxyCount());
			SAMLRequirementEnumeration ea = source.getEncryptAssertions();
			// Per defecte CONDITIONAL
			saml2ecp.setEncryptAssertions(ea != null ? ea.getValue() : SAMLRequirementEnumeration.CONDITIONAL.getValue());
			SAMLRequirementEnumeration eni = source.getEncryptNameIds();
			// Per defecte NEVER
			saml2ecp.setEncryptNameIds(eni != null ? eni.getValue() : SAMLRequirementEnumeration.NEVER.getValue());
			// propis
			saml2ecp.setIncludeAttributeStatement(source.getIncludeAttributeStatement());
			saml2ecp.setLocalityAddress(source.getLocalityAddress());
			saml2ecp.setLocalityDNSName(source.getLocalityDNSName());
			target = saml2ecp;
		} else if (SamlProfileEnumeration.SAML2_SSO.equals(source.getClasse())) {
			// heretats
			Saml2SSOProfileEntity entity = (Saml2SSOProfileEntity) target;
			entity.setOutboundArtifactType(source.getOutboundArtifactType());
			entity.setAssertionLifetime(source.getAssertionLifetime());
			entity.setAssertionProxyCount(source.getAssertionProxyCount());
			entity.setIncludeAttributeStatement(source.getIncludeAttributeStatement());
			SAMLRequirementEnumeration ea = source.getEncryptAssertions();
			// Per defecte CONDITIONAL
			entity.setEncryptAssertions(ea != null ? ea.getValue() : SAMLRequirementEnumeration.CONDITIONAL.getValue());
			SAMLRequirementEnumeration eni = source.getEncryptNameIds();
			// Per defecte NEVER
			entity.setEncryptNameIds(eni != null ? eni.getValue() : SAMLRequirementEnumeration.NEVER.getValue());
			// propis
			entity.setMaximumSPSessionLifetime(source.getMaximumSPSessionLifetime());
			target = entity;
		} else if (SamlProfileEnumeration.OPENID.equals(source.getClasse())) {
			// heretats
			OpenidProfileEntity entity = (OpenidProfileEntity) target;
			entity.setAuthorizationEndpoint(source.getAuthorizationEndpoint());
			entity.setEnabled(source.getEnabled());
			entity.setTokenEndpoint(source.getTokenEndpoint());
			entity.setUserInfoEndpoint(source.getUserInfoEndpoint());
			entity.setRevokeEndpoint(source.getRevokeEndpoint());
			target = entity;
		} else if (SamlProfileEnumeration.CAS.equals(source.getClasse())) {
			// heretats
			CasProfileEntity entity = (CasProfileEntity) target;
			entity.setEnabled(source.getEnabled());
			target = entity;
		} else if (SamlProfileEnumeration.RADIUS.equals(source.getClasse())) {
			// heretats
			RadiusProfileEntity entity = (RadiusProfileEntity) target;
			entity.setAcctPort(source.getAcctPort());
			entity.setAuthPort(source.getAuthPort());
			entity.setChap(source.getChap());
			entity.setPap(source.getPap());
			entity.setMsChap(source.getMsChap());
			entity.setEnabled(source.getEnabled());
			entity.setFreeRadiusPort(source.getFreeRadiusPort());
			entity.setSecurePort(source.getSecurePort());
			target = entity;
		} else if (SamlProfileEnumeration.TACACS_PLUS.equals(source.getClasse())) {
			// heretats
			TacacsProfileEntity entity = (TacacsProfileEntity) target;
			entity.setAuthPort(source.getAuthPort());
			entity.setChap(source.getChap());
			entity.setPap(source.getPap());
			entity.setMsChap(source.getMsChap());
			entity.setAscii(source.getAscii());
			entity.setSsl(source.getSsl());
			entity.setEnabled(source.getEnabled());
			target = entity;
		} else if (SamlProfileEnumeration.WS_FEDERATION.equals(source.getClasse())) {
			// heretats
			WsfedProfileEntity entity = (WsfedProfileEntity) target;
			entity.setEnabled(source.getEnabled());
			target = entity;
		} else if (SamlProfileEnumeration.SSE.equals(source.getClasse())) {
			// heretats
			SseProfileEntity entity = (SseProfileEntity) target;
			entity.setEnabled(source.getEnabled());
			target = entity;
		} else {
			// Res més... per als SAMLProfile
		}

	}

}