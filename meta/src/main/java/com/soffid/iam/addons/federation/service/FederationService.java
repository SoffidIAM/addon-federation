//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.FederationMemberSession;
import com.soffid.iam.addons.federation.common.OauthToken;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.common.UserConsent;
import com.soffid.iam.addons.federation.model.AllowedScopeEntity;
import com.soffid.iam.addons.federation.model.AllowedScopeRoleEntity;
import com.soffid.iam.addons.federation.model.AuthenticationMethodEntity;
import com.soffid.iam.addons.federation.model.CasProfileEntity;
import com.soffid.iam.addons.federation.model.FederationMemberSessionEntity;
import com.soffid.iam.addons.federation.model.ImpersonationEntity;
import com.soffid.iam.addons.federation.model.KerberosKeytabEntity;
import com.soffid.iam.addons.federation.model.OauthTokenEntity;
import com.soffid.iam.addons.federation.model.OauthTokenScopeEntity;
import com.soffid.iam.addons.federation.model.RadiusProfileEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderReturnUrlEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderRoleEntity;
import com.soffid.iam.addons.federation.model.UserConsentEntity;
import com.soffid.iam.addons.federation.roles.federation_serviceProvider;
import com.soffid.iam.addons.federation.roles.federation_update;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.model.SamlRequestEntity;
import com.soffid.iam.service.MailService;
import com.soffid.mda.annotation.*;

import es.caib.bpm.servei.BpmEngine;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.model.RolEntity;
import es.caib.seycon.ng.servei.AplicacioService;
import es.caib.seycon.ng.servei.DadesAddicionalsService;
import es.caib.seycon.ng.servei.DispatcherService;
import es.caib.seycon.ng.servei.DominiService;
import es.caib.seycon.ng.servei.DominiUsuariService;
import es.caib.seycon.ng.servei.SessioService;
import es.caib.seycon.ng.servei.UsuariService;
import es.caib.seycon.ng.sync.servei.LogonService;
import roles.Tothom;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Federation Service.
 * 
 * Common services for user authentication:
 * 
 * - generateSamlRequest: generates a SAML request 
 * - authenticate: parses and validates a SAML request, generating a sessino cookie
 * - checkSessionCookie: parses and validates a SAML session cookie
 * 
 */
import org.springframework.transaction.annotation.Transactional;

@Service ( serverPath="/seycon/FederationService",
	 serverRole="agent",
	 translatedName="FederationService",
	 translatedPackage="com.soffid.iam.addons.federation.service")
@Depends ({com.soffid.iam.addons.federation.model.EntityGroupEntity.class,
	es.caib.seycon.ng.servei.InternalPasswordService.class,
	es.caib.seycon.ng.model.DispatcherEntity.class,
	es.caib.seycon.ng.model.PoliticaContrasenyaEntity.class,
	es.caib.seycon.ng.servei.PasswordService.class,
	es.caib.seycon.ng.servei.UsuariService.class,
	es.caib.seycon.ng.servei.DadesAddicionalsService.class,
	es.caib.seycon.ng.model.DadaUsuariEntity.class,
	es.caib.seycon.ng.model.DominiContrasenyaEntity.class,
	es.caib.seycon.ng.model.UsuariEntity.class,
	es.caib.seycon.ng.servei.LlistesDeCorreuService.class,
	es.caib.seycon.ng.servei.AccountService.class,
	com.soffid.iam.addons.federation.model.FederationMemberEntity.class,
	com.soffid.iam.addons.federation.model.PolicyEntity.class,
	com.soffid.iam.addons.federation.model.PolicyConditionEntity.class,
	com.soffid.iam.addons.federation.model.AttributePolicyEntity.class,
	com.soffid.iam.addons.federation.model.AttributeEntity.class,
	com.soffid.iam.addons.federation.model.IdentityProviderEntity.class,
	com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity.class,
	com.soffid.iam.addons.federation.model.ServiceProviderEntity.class,
	com.soffid.iam.addons.federation.model.AttributeConditionEntity.class,
	com.soffid.iam.addons.federation.model.ProfileEntity.class,
	com.soffid.iam.addons.federation.model.SamlProfileEntity.class,
	com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity.class,
	com.soffid.iam.addons.federation.model.Saml1ArtifactResolutionProfileEntity.class,
	com.soffid.iam.addons.federation.model.Saml2ArtifactResolutionProfileEntity.class,
	com.soffid.iam.addons.federation.model.Saml2ECPProfileEntity.class,
	com.soffid.iam.addons.federation.model.Saml1AttributeQueryProfileEntity.class,
	com.soffid.iam.addons.federation.model.Saml2AttributeQueryProfileEntity.class,
	RadiusProfileEntity.class,
	CasProfileEntity.class,
	com.soffid.iam.addons.federation.model.Saml2SSOProfileEntity.class,
	es.caib.seycon.ng.servei.ConfiguracioService.class,
	es.caib.seycon.ng.model.AuditoriaEntity.class,
	SamlRequestEntity.class,
	DominiService.class,
	DispatcherService.class,
	DominiUsuariService.class,
	SessioService.class,
	LogonService.class,
	KerberosKeytabEntity.class,
	AuthenticationMethodEntity.class,
	UserBehaviorService.class,
	OauthTokenEntity.class,
	OauthTokenScopeEntity.class,
	MailService.class,
	BpmEngine.class,
	UserConsentEntity.class,
	ImpersonationEntity.class,
	ServiceProviderRoleEntity.class,
	RolEntity.class,
	AllowedScopeEntity.class,
	AllowedScopeRoleEntity.class,
	AplicacioService.class,
	ServiceProviderReturnUrlEntity.class,
	FederationMemberSessionEntity.class
})
public abstract class FederationService {

	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_create.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.EntityGroup create(
		com.soffid.iam.addons.federation.common.EntityGroup entityGroup)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.EntityGroup update(
		com.soffid.iam.addons.federation.common.EntityGroup entityGroup)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.EntityGroup entityGroup)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_create.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.FederationMember create(
		com.soffid.iam.addons.federation.common.FederationMember federationMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.FederationMember update(
		com.soffid.iam.addons.federation.common.FederationMember federationMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.FederationMember federationMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_create.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.SAMLProfile create(
		com.soffid.iam.addons.federation.common.SAMLProfile samlProfile)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.SAMLProfile update(
		com.soffid.iam.addons.federation.common.SAMLProfile samlProfile)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.SAMLProfile samlProfile)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_create.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.Policy create(
		com.soffid.iam.addons.federation.common.Policy policy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.Policy update(
		com.soffid.iam.addons.federation.common.Policy policy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.Policy policy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_attribute_create.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.Attribute create(
		com.soffid.iam.addons.federation.common.Attribute attribute)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_attribute_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.Attribute update(
		com.soffid.iam.addons.federation.common.Attribute attribute)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_attribute_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.Attribute attribute)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.EntityGroupMember> findEntityGroupByNom(
		java.lang.String nom)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.FederationMember> findFederationMemberByEntityGroupAndPublicIdAndTipus(
		@Nullable java.lang.String entityGroupName, 
		@Nullable java.lang.String publicId, 
		java.lang.String tipus)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.FederationMember findFederationMemberByClientID(
		java.lang.String clientId)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.FederationMember findFederationMemberByPublicId(
		java.lang.String publicId)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public Collection<com.soffid.iam.addons.federation.common.FederationMember> findVirtualIdentityProvidersForIdentitiProvider(
		java.lang.String publicId)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.Policy> findPolicies()
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.EntityGroupMember> findChildren(
		com.soffid.iam.addons.federation.common.EntityGroupMember groupMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_create.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.EntityGroupMember create(
		com.soffid.iam.addons.federation.common.EntityGroupMember entityGroupMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.EntityGroupMember update(
		com.soffid.iam.addons.federation.common.EntityGroupMember entityGroupMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.EntityGroupMember entityGroupMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.SAMLProfile> findProfilesByFederationMember(
		com.soffid.iam.addons.federation.common.FederationMember federationMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	@Description("Returns all profiles, including those undefined")
	public java.util.Collection<com.soffid.iam.addons.federation.common.SAMLProfile> findAllProfilesByFederationMember(
		com.soffid.iam.addons.federation.common.FederationMember federationMember)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.lang.String[] generateKeys(String name)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_attribute_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.Attribute> findAtributs(
		@Nullable java.lang.String name, 
		@Nullable java.lang.String shortName, 
		@Nullable java.lang.String oid)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_create.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.PolicyCondition create(
		com.soffid.iam.addons.federation.common.PolicyCondition policyCondition)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.PolicyCondition update(
		com.soffid.iam.addons.federation.common.PolicyCondition policyCondition)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.PolicyCondition policyCondition)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_create.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.AttributePolicyCondition create(
		com.soffid.iam.addons.federation.common.AttributePolicyCondition attributeCondition)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.AttributePolicyCondition update(
		com.soffid.iam.addons.federation.common.AttributePolicyCondition attributeCondition)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.AttributePolicyCondition attributeCondition)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.AttributePolicy create(
		com.soffid.iam.addons.federation.common.AttributePolicy attributePolicy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public com.soffid.iam.addons.federation.common.AttributePolicy update(
		com.soffid.iam.addons.federation.common.AttributePolicy attributePolicy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_delete.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void delete(
		com.soffid.iam.addons.federation.common.AttributePolicy attributePolicy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.AttributePolicyCondition> findAttributePolicy(
		com.soffid.iam.addons.federation.common.Policy policy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.PolicyCondition> findPolicyCondition(
		com.soffid.iam.addons.federation.common.Policy policy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_policy_query.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.util.Collection<com.soffid.iam.addons.federation.common.AttributePolicyCondition> findAttributeCondition(
		com.soffid.iam.addons.federation.common.AttributePolicy attributePolicy)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Operation ( grantees={com.soffid.iam.addons.federation.roles.federation_update.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.lang.String generatePKCS10(
		com.soffid.iam.addons.federation.common.FederationMember federationMember,
		String privateKey, String publicKey)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	
	@Operation(grantees={federation_update.class})
	public String[] parsePkcs12(
		byte pkcs12[],
		@Nullable
		String password) { return null;	}
	
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.lang.String getPolicyDescriptionForAccount(
		java.lang.String account, 
		@Nullable java.lang.String dispatcher)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Transactional(rollbackFor={java.lang.Exception.class})
	public java.lang.String getPolicyDescriptionForUserType(
		java.lang.String userType, 
		@Nullable java.lang.String dispatcher)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Transactional(rollbackFor={java.lang.Exception.class})
	public es.caib.seycon.ng.comu.PolicyCheckResult checkPolicy(
		java.lang.String userType, 
		@Nullable java.lang.String dispatcher, 
		es.caib.seycon.ng.comu.Password password)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void sendActivationEmail(
		java.lang.String user, 
		java.lang.String activationUrl, 
		java.lang.String organizationName)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Transactional(rollbackFor={java.lang.Exception.class})
	public es.caib.seycon.ng.comu.Usuari verifyActivationEmail(
		java.lang.String key)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void sendRecoverEmail(
		java.lang.String email, 
		java.lang.String activationUrl, 
		java.lang.String organizationName)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	@Transactional(rollbackFor={java.lang.Exception.class})
	public es.caib.seycon.ng.comu.Usuari verifyRecoverEmail(
		java.lang.String key)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Transactional(rollbackFor={java.lang.Exception.class})
	public es.caib.seycon.ng.comu.Usuari registerUser(
		String identityProvider,
		String url,
		java.lang.String dispatcher, 
		es.caib.seycon.ng.comu.Usuari usuari, 
		java.util.Map additionalData, 
		es.caib.seycon.ng.comu.Password password)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	 return null;
	}

	@Operation(grantees={federation_serviceProvider.class})
	@Description("Generates a SAML request to formard to the IdP")
	SamlRequest generateSamlRequest (String serviceProvider, String identityProvider,
			@Nullable String subject,
			long sessionSeconds) {return null;}
	
	@Operation(grantees={federation_serviceProvider.class})
	@Description("Generates a SAML request to perform global logout. Use forced when "
			+ "is the system admin who enforces the logout. Leave to false when is "
			+ "the user who requests to log out. \n"
			+ "Enable backchannel to enable SAML logout process.")
	SamlRequest generateSamlLogoutRequest (String serviceProvider, String identityProvider,
			String subject,
			boolean forced,
			boolean backChannel) {return null;}
	
	@Operation(grantees={federation_serviceProvider.class})
	@Description("Checks SAML response")
	SamlValidationResults authenticate(String serviceProviderName, String protocol, 
			Map<String,String> response,
			boolean autoProvision) {return null;}

	@Operation(grantees={federation_serviceProvider.class})
	@Description("Validates SAML cookie")
	SamlValidationResults validateSessionCookie(String sessionCookie) {return null;}

	@Operation(grantees={federation_serviceProvider.class})
	@Description("Expires SAML cookie")
	void expireSessionCookie(String sessionCookie) {}

	@Operation(grantees={federation_serviceProvider.class})
	@Description("Finds identity provider for subject")
	String searchIdpForUser(String userName) {return null;}

	@Operation(grantees={federation_serviceProvider.class})
	@Description("Creates a virtual IdP session")
	SamlValidationResults authenticate(String serviceProvider, String identityProvider, 
			String user, String password, long sessionSeconds) {return null;}


	@Operation(grantees={federation_serviceProvider.class})
	@Description("Creates a virtual IdP session")
	Usuari findAccountOwner(String principalName, String identityProvider,
			String soffidIdentityProvider,
			Map<String, Object> properties, boolean autoProvision) {return null;}

	
	@Operation
	@Description("Computes the loginHint to present to a third party IdP")
	String getLoginHint(String idp, String loginHint) {return null;}
	
	/* Token services */
	OauthToken createOauthToken(OauthToken token) {return null;}
	void deleteOauthToken(OauthToken token) {}
	void updateOauthToken(OauthToken token) {}
	OauthToken findOauthTokenByAuthorizationCode(String idp, String authorizationCode) {return null;}
	OauthToken findOauthTokenByToken(String idp, String token) {return null;}
	OauthToken findOauthTokenByRefreshToken(String idp, String token) {return null;}
	String filterScopes(@Nullable String requestedScopes, String user, String system, String serviceProvider) {return null;}
	
	/* Consent */
	boolean hasConsent(String userName, String serviceProvider) {return false;}
	void addConsent(String userName, String serviceProvider) {}
	@Operation(grantees= {Tothom.class}) Collection<UserConsent> findUserConsents(){ return null;}
	@Operation(grantees= {Tothom.class}) void deleteUserConsent(UserConsent userConsent){}
	
	
	@Description("Finds soffid identity providers")
	List<FederationMember> findSoffidIdentityProviders() { return null;}
	
	List<FederationMemberSession> findFederationMemberSessions(Long sessionId) {return null;}
	FederationMemberSession createFederatioMemberSession(FederationMemberSession sessiod) {return null;}
	void deleteFederatioMemberSession(FederationMemberSession session) {}
	List<FederationMemberSession> findFederationMemberSessions(String publicId, String uid) {return null;}
	List<OauthToken> findOauthTokenBySessionId(Long sessionId) {return null;}
}
