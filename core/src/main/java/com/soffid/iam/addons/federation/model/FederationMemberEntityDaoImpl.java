// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.model;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.addons.federation.common.AllowedScope;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.api.Password;
import com.soffid.iam.model.GroupEntity;
import com.soffid.iam.model.UserTypeEntity;

/**
 * @see com.soffid.iam.addons.federation.model.FederationMemberEntity
 */
public class FederationMemberEntityDaoImpl extends com.soffid.iam.addons.federation.model.FederationMemberEntityDaoBase {
	/**
	 * @see com.soffid.iam.addons.federation.model.FederationMemberEntityDao#toFederationMember(com.soffid.iam.addons.federation.model.FederationMemberEntity,
	 *      com.soffid.iam.addons.federation.common.FederationMember)
	 */
	public void toFederationMember(com.soffid.iam.addons.federation.model.FederationMemberEntity source,
			com.soffid.iam.addons.federation.common.FederationMember target) {
		// @todo verify behavior of toFederationMember
		super.toFederationMember(source, target);
		// WARNING! No conversion for target.entityGroup (can't convert
		// source.getEntityGroup():com.soffid.iam.addons.federation.model.EntityGroupEntity to
		// com.soffid.iam.addons.federation.common.EntityGroup
		toFederationMemberCustom(source, target);
	}

	private void toFederationMemberCustom(com.soffid.iam.addons.federation.model.FederationMemberEntity source,
			com.soffid.iam.addons.federation.common.FederationMember target) {
		
		if (source.getMetadades()!=null) {
			try {
				target.setMetadades(new String(source.getMetadades(),"UTF-8")); //$NON-NLS-1$
			} catch (UnsupportedEncodingException io) {
				io.printStackTrace();
			}
		}

		// Afegim el entityGroup als FM
		if (source.getEntityGroup() != null) {
			EntityGroup eg = getEntityGroupEntityDao().toEntityGroup(source.getEntityGroup());
			target.setEntityGroup(eg);
		}

		target.setPublicKey(source.getPublicKey());
		target.setPrivateKey(source.getPrivateKey());
		target.setCertificateChain(source.getCertificateChain());
		target.setInternal(source.isInternal());
		target.setDisableSSL(source.getDisableSSL());
		target.setHostName(source.getHostName());
		target.setStandardPort(source.getStandardPort());

		if (source instanceof IdentityProviderEntity) {
			target.setClasse("I"); //$NON-NLS-1$
			// IdentityProvider
			// Obtenim l'instància
			IdentityProviderEntity idp = (IdentityProviderEntity) source;
			// Heretats de VIP
			target.setPublicId(idp.getPublicId());
			if (idp.getIdpType() == null)
				target.setIdpType(idp.isInternal()? IdentityProviderType.SOFFID: IdentityProviderType.SAML);
			else
			{
				target.setIdpType(idp.getIdpType());
				target.setInternal(idp.getIdpType().equals(IdentityProviderType.SOFFID));
			}
			target.setLoginHintScript(idp.getLoginHintScript());
			target.setOauthKey(idp.getOauthKey());
			target.setOauthSecret(idp.getOauthSecret() == null ? null: Password.decode(idp.getOauthSecret()));
			// Propis
			target.setClientCertificatePort(idp.getClientCertificatePort());
			
			target.setAuthenticationMethods(idp.getAuthenticationMethods());
			if (target.getAuthenticationMethods() == null)
			{
				StringBuffer s = new StringBuffer();
				s.append("P ");
				if (idp.isAllowCertificate())
					s.append("C ");
				if (idp.getEnableKerberos() != null && idp.getEnableKerberos().booleanValue())
					s.append("K ");
				if (idp.getIdentityBroker() != null && idp.getIdentityBroker().booleanValue())
					s.append("E ");
				target.setAuthenticationMethods(s.toString().trim());
				
			}
			target.setAlwaysAskForCredentials(idp.getAlwaysAskForCredentials());
			// SSL Certs
			target.setSslPrivateKey(idp.getSslPrivateKey());
			target.setSslPublicKey(idp.getSslPublicKey());
			target.setSslCertificate(idp.getSslCertificate());
			target.setSslClientCertificateHeader(idp.getSslClientCertificateHeader());
			// Other options
			target.setKerberosDomain(idp.getKerberosDomain());
			if (idp.getSsoCookieName() == null || idp.getSsoCookieName().trim().isEmpty())
				target.setSsoCookieName("soffid_sso_session");
			else
				target.setSsoCookieName(idp.getSsoCookieName());
			target.setSsoCookieDomain(idp.getSsoCookieDomain());
			target.setSessionTimeout(idp.getSessionTimeout());
			target.setRegisterExternalIdentities(idp.getRegisterExternalIdentities());
			// Service providers
			if (idp.getServiceProviderVirtualIdentityProvider() != null) {
				Collection spse = idp.getServiceProviderVirtualIdentityProvider();
				ArrayList sps = new ArrayList(spse.size());
				for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = spse.iterator(); it.hasNext();) {
					ServiceProviderVirtualIdentityProviderEntity spvp = it.next();
					ServiceProviderEntity sp = spvp.getServiceProvider();
					sps.add(toFederationMember(sp));
				}
				target.setServiceProvider(sps);
			}
			
			generateRegisterValues(target, idp);
			loadAuthenticatioMethods (idp, target);

		} else if (source instanceof VirtualIdentityProviderEntity) {
			target.setClasse("V"); //$NON-NLS-1$
			// VirtualIdentityProvider
			// Obtenim l'instància
			VirtualIdentityProviderEntity vip = (VirtualIdentityProviderEntity) source;
			// Heretats de VIP
			target.setPublicId(vip.getPublicId());
			target.setPrivateKey(vip.getPrivateKey());
			target.setPublicKey(vip.getPublicKey());
			target.setCertificateChain(vip.getCertificateChain());
			target.setLoginHintScript(vip.getLoginHintScript());
			
			target.setAuthenticationMethods(vip.getAuthenticationMethods());
			if (target.getAuthenticationMethods() == null)
			{
				StringBuffer s = new StringBuffer();
				s.append("P ");
				if (vip.isAllowCertificate())
					s.append("C ");
				if (vip.getEnableKerberos() != null && vip.getEnableKerberos().booleanValue())
					s.append("K ");
				target.setAuthenticationMethods(s.toString().trim());
				
			}
			target.setAlwaysAskForCredentials(vip.getAlwaysAskForCredentials());
			target.setKerberosDomain(vip.getKerberosDomain());
			target.setSsoCookieDomain(vip.getSsoCookieDomain());
			target.setSsoCookieName(vip.getSsoCookieName());
			// Default IDP
			if (vip.getDefaultIdentityProvider() != null) {
				FederationMember dip = toFederationMember(vip.getDefaultIdentityProvider());
				target.setDefaultIdentityProvider(dip);
			}
			// Service providers
			if (vip.getServiceProviderVirtualIdentityProvider() != null) {
				Collection spse = vip.getServiceProviderVirtualIdentityProvider();
				ArrayList sps = new ArrayList(spse.size());
				for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = spse.iterator(); it.hasNext();) {
					ServiceProviderVirtualIdentityProviderEntity spvp = it.next();
					ServiceProviderEntity sp = spvp.getServiceProvider();
					sps.add(toFederationMember(sp));
				}
				target.setServiceProvider(sps);
			}
			
			generateRegisterValues(target, vip);
			loadAuthenticatioMethods (vip, target);

		} else if (source instanceof ServiceProviderEntity) {
			target.setClasse("S"); //$NON-NLS-1$
			// ServiceProvicer
			// Obtenim l'instància
			ServiceProviderEntity sp = (ServiceProviderEntity) source;
			// Heretats de VIP
			if (source.isInternal() && sp.getServiceProviderType() == ServiceProviderType.SAML)
				target.setServiceProviderType(ServiceProviderType.SOFFID_SAML);
			else
				target.setServiceProviderType(sp.getServiceProviderType());
			target.setPublicId(sp.getPublicId());
			target.setNameIdFormat(sp.getNameIdFormat());
			target.setCertificateChain(sp.getCertificateChain());
			target.setUidExpression(sp.getUidExpression());
			target.setConsent(sp.getConsent());
			if (sp.getOpenidMechanism() == null || sp.getOpenidMechanism().isEmpty() )
				target.setOpenidMechanism(new HashSet<String>());
			else
				target.setOpenidMechanism( new HashSet<String> ( Arrays.asList( sp.getOpenidMechanism().split(",") )) );
			target.setOpenidClientId(sp.getOpenidClientId());
			target.setOpenidSecret(sp.getOpenidSecret());
			List<String> l = new LinkedList<>();
			List<String> l2 = new LinkedList<>();
			if (sp.getOpenidUrl() != null && ! sp.getOpenidUrl().trim().isEmpty())
				l.add(sp.getOpenidUrl());
			for (ServiceProviderReturnUrlEntity url: sp.getReturnUrls())
				if ("logout".equals(url.getType()))
					l2.add(url.getUrl());
				else
					l.add(url.getUrl());
			target.setOpenidUrl(l);
			target.setOpenidLogoutUrl(l2);
			target.setOpenidLogoutUrlBack(sp.getOpenidLogoutUrlBack());
			target.setOpenidLogoutUrlFront(sp.getOpenidLogoutUrlFront());
			// Radius attributes
			target.setSourceIps(sp.getSourceIps());
			target.setRadiusSecret(sp.getRadiusSecret() == null ? null: Password.decode(sp.getRadiusSecret()));
			// Virtual Identity Provider (informatiu)
			// Service providers
			if (sp.getServiceProviderVirtualIdentityProvider() != null) {
				Collection spve = sp.getServiceProviderVirtualIdentityProvider();
				ArrayList spv = new ArrayList(spve.size());
				for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = spve.iterator(); it.hasNext();) {
					ServiceProviderVirtualIdentityProviderEntity spvp = it.next();
					VirtualIdentityProviderEntity vp = spvp.getVirtualIdentityProvider();
					//spv.add(toFederationMember(vp));
					FederationMember nomesDesc = new FederationMember();
					nomesDesc.setPublicId(vp.getPublicId());
					spv.add(nomesDesc);// Afegim només el publicID (referència)
				}
				target.setVirtualIdentityProvider(spv);
			}
			if (sp.getSystem() == null)
				target.setSystem(null);
			else
				target.setSystem(sp.getSystem().getName());
			for (ImpersonationEntity fip: sp.getImpersonations()) {
				target.getImpersonations().add(fip.getUrl());
			}
			target.setRoles(new LinkedList<String>());
			for (ServiceProviderRoleEntity ra: sp.getRoles()) {
				target.getRoles().add(ra.getRole().getName()+"@"+ra.getRole().getSystem().getName());
			}
			loadScopes(sp, target);
		}
		
		target.getKeytabs().clear();
		if (source instanceof VirtualIdentityProviderEntity)
		{
			target.getKeytabs().addAll(
					getKerberosKeytabEntityDao().toKerberosKeytabList(
							((VirtualIdentityProviderEntity) source).getKeytabs()));
		}

	}

	private void loadScopes(ServiceProviderEntity sp, FederationMember target) {
		target.setAllowedScopes( getAllowedScopeEntityDao().toAllowedScopeList(sp.getAllowedScopes()));
		if (target.getAllowedScopes().isEmpty()) {
			target.getAllowedScopes().add(new AllowedScope(null, "*", new LinkedList<String>()));
		}
		for (AllowedScope scope: target.getAllowedScopes()) {
			if (scope.getScope().equals("openid"))
			{
				return;
			}
		}
		target.getAllowedScopes().add(new AllowedScope(null, "openid", new LinkedList<String>()));
	}

	private void loadAuthenticatioMethods(VirtualIdentityProviderEntity source, FederationMember target) {
		List<AuthenticationMethodEntity> authenticationMethodList = new LinkedList<AuthenticationMethodEntity>(
				source.getExtendedAuthenticationMethods());
		authenticationMethodList.sort(new Comparator<AuthenticationMethodEntity>() {
			public int compare(AuthenticationMethodEntity o1, AuthenticationMethodEntity o2) {
				return o1.getOrder().compareTo(o2.getOrder());
			}
		});
		target.getExtendedAuthenticationMethods().addAll(
				getAuthenticationMethodEntityDao().toAuthenticationMethodList(authenticationMethodList));
	}

	private void generateRegisterValues(
			com.soffid.iam.addons.federation.common.FederationMember target,
			VirtualIdentityProviderEntity vip) {
		target.setAuthenticationMethods(vip.getAuthenticationMethods());
		if (target.getAuthenticationMethods() == null)
		{
			StringBuffer s = new StringBuffer();
			s.append("P ");
			if (vip.isAllowCertificate())
				s.append("C ");
			if (vip.getEnableKerberos() != null && vip.getEnableKerberos().booleanValue())
				s.append("K ");
			target.setAuthenticationMethods(s.toString().trim());
			
		}
		target.setAlwaysAskForCredentials(vip.getAlwaysAskForCredentials());
		target.setAllowRecover(vip.isAllowRecover());
		target.setAllowRegister(vip.isAllowRegister());
		target.setRegisterWorkflow(vip.getRegisterWorkflow());
		target.setUserTypeToRegister(vip.getUserTypeToRegister() == null? null :
			vip.getUserTypeToRegister().getName());
		target.setGroupToRegister(vip.getGroupToRegister() == null? 
				null: 
				vip.getGroupToRegister().getName());
		target.setMailHost(vip.getMailHost());
		target.setMailSenderAddress(vip.getMailSenderAddress());
	}

	/**
	 * @see com.soffid.iam.addons.federation.model.FederationMemberEntityDao#toFederationMember(com.soffid.iam.addons.federation.model.FederationMemberEntity)
	 */
	public com.soffid.iam.addons.federation.common.FederationMember toFederationMember(final com.soffid.iam.addons.federation.model.FederationMemberEntity entity) {
		// @todo verify behavior of toFederationMember
		return super.toFederationMember(entity);
	}

	/**
	 * Retrieves the entity object that is associated with the specified value
	 * object from the object store. If no such entity object exists in the
	 * object store, a new, blank entity is created
	 */
	private com.soffid.iam.addons.federation.model.FederationMemberEntity loadFederationMemberEntityFromFederationMember(
			com.soffid.iam.addons.federation.common.FederationMember federationMember) {
		com.soffid.iam.addons.federation.model.FederationMemberEntity federationMemberEntity = null;

		if (federationMember.getId() != null) {
			// Carreguem segons el tipus de Classe
			if ("I".equals(federationMember.getClasse())) { //$NON-NLS-1$
				federationMemberEntity = findIDPById(federationMember.getId());
			} else if ("S".equals(federationMember.getClasse())) { //$NON-NLS-1$
				federationMemberEntity = findSPById(federationMember.getId());
			} else if ("V".equals(federationMember.getClasse())) { //$NON-NLS-1$
				federationMemberEntity = findVIPById(federationMember.getId());
			} else {
				federationMemberEntity = load(federationMember.getId());
			}
		}

		if (federationMemberEntity == null) {
			if ("I".equals(federationMember.getClasse())) { //$NON-NLS-1$
				federationMemberEntity = newIdentityProviderEntity();
			} else if ("S".equals(federationMember.getClasse())) { //$NON-NLS-1$
				federationMemberEntity = newServiceProviderEntity();
			} else if ("V".equals(federationMember.getClasse())) { //$NON-NLS-1$
				federationMemberEntity = newVirtualIdentityProviderEntity();
			} else {
				federationMemberEntity = newFederationMemberEntity();
			}

		}
		return federationMemberEntity;
	}

	/**
	 * @see com.soffid.iam.addons.federation.model.FederationMemberEntityDao#federationMemberToEntity(com.soffid.iam.addons.federation.common.FederationMember)
	 */
	public com.soffid.iam.addons.federation.model.FederationMemberEntity federationMemberToEntity(
			com.soffid.iam.addons.federation.common.FederationMember federationMember) {

		com.soffid.iam.addons.federation.model.FederationMemberEntity entity = this.loadFederationMemberEntityFromFederationMember(federationMember);
		this.federationMemberToEntity(federationMember, entity, true);
		return entity;
	}

	/**
	 * @see com.soffid.iam.addons.federation.model.FederationMemberEntityDao#federationMemberToEntity(com.soffid.iam.addons.federation.common.FederationMember,
	 *      com.soffid.iam.addons.federation.model.FederationMemberEntity)
	 */
	public void federationMemberToEntity(com.soffid.iam.addons.federation.common.FederationMember source,
			com.soffid.iam.addons.federation.model.FederationMemberEntity target, boolean copyIfNull) {
		super.federationMemberToEntity(source, target, copyIfNull);
		federationMemberToEntityCustom(source, target);
	}

	private void federationMemberToEntityCustom(com.soffid.iam.addons.federation.common.FederationMember source,
			com.soffid.iam.addons.federation.model.FederationMemberEntity target) {
		// Copiar atribut metadades de pare fme i entitygroup

		// Metadades
		if (source.getMetadades() != null) {
			try {
				target.setMetadades(source.getMetadades().getBytes("UTF-8")); //$NON-NLS-1$
			} catch (UnsupportedEncodingException io) {
				io.printStackTrace();
			}	
		}

		EntityGroup entityGroup = source.getEntityGroup();
		if (entityGroup != null && entityGroup.getId() != null) {
			EntityGroupEntity entityGroupEntity = getEntityGroupEntityDao().load(entityGroup.getId());
			target.setEntityGroup(entityGroupEntity);
		} // sino donarà error

		// Transformació a classes filles (IDP, VIP, SP)
		if ("I".equals(source.getClasse())) { //$NON-NLS-1$
			// IdentityProvider
			IdentityProviderEntity idp = (IdentityProviderEntity) target;
			// Heretats de VIP
			if (source.getIdpType() == null)
				idp.setIdpType(source.getInternal() != null && source.getInternal().booleanValue()? 
						IdentityProviderType.SOFFID: IdentityProviderType.SAML);
			else
			{
				idp.setIdpType(source.getIdpType());
				idp.setInternal(source.getIdpType().equals(IdentityProviderType.SOFFID));
			}
			idp.setOauthKey(source.getOauthKey());
			idp.setOauthSecret(source.getOauthSecret() == null ? null: source.getOauthSecret().toString());
			idp.setLoginHintScript(source.getLoginHintScript());
			
			idp.setPublicId(source.getPublicId());
			idp.setPublicKey(source.getPublicKey());
			idp.setPrivateKey(source.getPrivateKey());
			if (source.getCertificateChain() != null)
				idp.setCertificateChain(source.getCertificateChain());
			
			// SSL Certs
			idp.setSslPrivateKey(source.getSslPrivateKey());
			idp.setSslPublicKey(source.getSslPublicKey());
			idp.setSslCertificate(source.getSslCertificate());
			idp.setSslClientCertificateHeader(source.getSslClientCertificateHeader());

			// Propis
			if (source.getInternal() != null)
				idp.setInternal(source.getInternal());
			idp.setHostName(source.getHostName());
			idp.setStandardPort(source.getStandardPort());
			idp.setClientCertificatePort(source.getClientCertificatePort());
			idp.setDisableSSL(source.getDisableSSL());
			
			idp.setKerberosDomain(source.getKerberosDomain());
			idp.setAuthenticationMethods(source.getAuthenticationMethods());
			idp.setAlwaysAskForCredentials(source.getAlwaysAskForCredentials());
			idp.setSsoCookieDomain(source.getSsoCookieDomain());
			idp.setSsoCookieName(source.getSsoCookieName());
			idp.setSessionTimeout(source.getSessionTimeout());
			idp.setRegisterExternalIdentities(source.getRegisterExternalIdentities());
			
			if (source.getServiceProvider() != null) {
				// els transformem tots i es guarden a sps
				List<FederationMemberEntity> sps = federationMemberToEntityList(source.getServiceProvider()); // federarionmember
				// Ara mirem els que ja tenim
				Collection rps = new ArrayList(getServiceProviderVirtualIdentityProviderEntityDao().findByVIP(idp.getId()));
				Collection relparfinal = new HashSet();

				if (rps != null)
					for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = rps.iterator(); it.hasNext();) {
						ServiceProviderVirtualIdentityProviderEntity rp = it.next();
						boolean trobat = false;
						for (Iterator<FederationMemberEntity> sit = sps.iterator(); !trobat && sit.hasNext();) {
							FederationMemberEntity sp = sit.next();
							if (rp.getServiceProvider().getId().equals(sp.getId())) {
								trobat = true;
								relparfinal.add(rp);
								// l'eliminem dels que s'han de crear
								sit.remove();
							}
						}
					}
				// En reparfinal tenim els que ja existien
				// afegim els nous
				if (sps != null) {
					for (Iterator<FederationMemberEntity> sit = sps.iterator(); sit.hasNext();) {
						ServiceProviderEntity sp = (ServiceProviderEntity) sit.next();
						ServiceProviderVirtualIdentityProviderEntity nou = 
								getServiceProviderVirtualIdentityProviderEntityDao().
									newServiceProviderVirtualIdentityProviderEntity();
						nou.setServiceProvider(sp);
						nou.setVirtualIdentityProvider(idp);
						relparfinal.add(nou);
					}
				}
				idp.setServiceProviderVirtualIdentityProvider(relparfinal);

			}			
			
			updateRegisterAttributes(source, idp);
			
			target = idp;
		} else if ("V".equals(source.getClasse())) { //$NON-NLS-1$
			// VirtualIdentityProvider
			VirtualIdentityProviderEntity vip = (VirtualIdentityProviderEntity) target;
			// Heretats de VIP
			vip.setPublicId(source.getPublicId());
			vip.setPrivateKey(source.getPrivateKey());
			vip.setPublicKey(source.getPublicKey());
			if (source.getCertificateChain() != null)
				vip.setCertificateChain(source.getCertificateChain());

			vip.setKerberosDomain(source.getKerberosDomain());
			vip.setAuthenticationMethods(source.getAuthenticationMethods());
			vip.setAlwaysAskForCredentials(source.getAlwaysAskForCredentials());
			vip.setSsoCookieDomain(source.getSsoCookieDomain());
			vip.setSsoCookieName(source.getSsoCookieName());
			vip.setLoginHintScript(source.getLoginHintScript());

			// Default IDP
			if (source.getDefaultIdentityProvider() != null) {
				FederationMember dip = source.getDefaultIdentityProvider();
				IdentityProviderEntity dipe = (IdentityProviderEntity) federationMemberToEntity(dip);
				vip.setDefaultIdentityProvider(dipe);
			}

			if (source.getServiceProvider() != null) {
				// els transformem tots i es guarden a sps
				List<FederationMemberEntity> sps = federationMemberToEntityList(source.getServiceProvider()); // federarionmember
				// Ara mirem els que ja tenim
				Collection rps = new ArrayList(getServiceProviderVirtualIdentityProviderEntityDao().findByVIP(vip.getId()));
				Collection relparfinal = new HashSet();

				if (rps != null)
					for (Iterator<ServiceProviderVirtualIdentityProviderEntity> it = rps.iterator(); it.hasNext();) {
						ServiceProviderVirtualIdentityProviderEntity rp = it.next();
						boolean trobat = false;
						for (Iterator<FederationMemberEntity> sit = sps.iterator(); !trobat && sit.hasNext();) {
							FederationMemberEntity sp = sit.next();
							if (rp.getServiceProvider().getId().equals(sp.getId())) {
								trobat = true;
								relparfinal.add(rp);
								// l'eliminem dels que s'han de crear
								sit.remove();
							}
						}
					}
				// En reparfinal tenim els que ja existien
				// afegim els nous
				if (sps != null) {
					for (Iterator<FederationMemberEntity> sit = sps.iterator(); sit.hasNext();) {
						ServiceProviderEntity sp = (ServiceProviderEntity) sit.next();
						ServiceProviderVirtualIdentityProviderEntity nou = 
								getServiceProviderVirtualIdentityProviderEntityDao().
									newServiceProviderVirtualIdentityProviderEntity();
						nou.setServiceProvider(sp);
						nou.setVirtualIdentityProvider(vip);
						relparfinal.add(nou);
					}
				}
				vip.setServiceProviderVirtualIdentityProvider(relparfinal);

			}
			
			updateRegisterAttributes(source, vip);

			target = vip;
		} else if ("S".equals(source.getClasse())) { //$NON-NLS-1$
			// ServiceProvicer
			// Obtenim l'instància
			ServiceProviderEntity sp = (ServiceProviderEntity) target;
			// Heretats de VIP
			sp.setServiceProviderType( source.getServiceProviderType() );
			sp.setInternal(source.getServiceProviderType() == ServiceProviderType.SOFFID_SAML);
			sp.setPublicId(source.getPublicId());
			sp.setNameIdFormat(source.getNameIdFormat());
			sp.setUidExpression(source.getUidExpression());
			sp.setConsent(source.getConsent());
			if (source.getCertificateChain() != null)
				sp.setCertificateChain(source.getCertificateChain());
			StringBuffer sb = new StringBuffer();
			for (String s: source.getOpenidMechanism())
			{
				if (sb.length()>0) sb.append(",");
				sb.append(s);
			}
			sp.setOpenidMechanism(sb.toString());
			sp.setOpenidClientId(source.getOpenidClientId());
			sp.setOpenidSecret(source.getOpenidSecret());
			sp.setOpenidUrl(null);
			sp.setOpenidLogoutUrlBack(source.getOpenidLogoutUrlBack());
			sp.setOpenidLogoutUrlFront(source.getOpenidLogoutUrlFront());
			
			if (source.getSystem() == null)
				sp.setSystem(null);
			else 
				sp.setSystem(getSystemEntityDao().findByName(source.getSystem()) );
			// Radius attributes
			sp.setSourceIps(source.getSourceIps());
			sp.setRadiusSecret(source.getRadiusSecret() == null ? null: source.getRadiusSecret().toString());

			// Aquí no guardem la relació SP-VIP (ServiceProviderVirtualIdentityProviderEntity)
			
			target = sp;
		}

	}

	private void updateRegisterAttributes(
			com.soffid.iam.addons.federation.common.FederationMember source,
			VirtualIdentityProviderEntity vip)  {
		vip.setAuthenticationMethods(source.getAuthenticationMethods());
		vip.setAlwaysAskForCredentials(source.getAlwaysAskForCredentials());
		vip.setAllowRecover(source.isAllowRecover());
		vip.setAllowRegister(source.isAllowRegister());
		vip.setMailHost(source.getMailHost());
		vip.setMailSenderAddress(source.getMailSenderAddress());
		vip.setRegisterWorkflow(source.getRegisterWorkflow());
		if (source.getUserTypeToRegister() == null)
		{
			vip.setUserTypeToRegister(null);
		}
		else
		{
			UserTypeEntity tipus = getUserTypeEntityDao().findByName(source.getUserTypeToRegister());
			if (tipus == null)
				throw new IllegalArgumentException(String.format("Invalid user type %s", source.getUserTypeToRegister()));
			vip.setUserTypeToRegister(tipus);
		}

		if (source.getGroupToRegister() == null)
		{
			vip.setGroupToRegister(null);
		}
		else
		{
			GroupEntity grup = getGroupEntityDao().findByName(source.getGroupToRegister());
			if (grup == null)
				throw new IllegalArgumentException(String.format("Invalid group %s", source.getGroupToRegister()));
			vip.setGroupToRegister(grup);
		}
	}

}
