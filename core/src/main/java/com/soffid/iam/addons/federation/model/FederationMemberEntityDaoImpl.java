// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.model;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.model.GrupEntity;
import es.caib.seycon.ng.model.TipusUsuariEntity;

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

		if (source instanceof IdentityProviderEntity) {
			target.setClasse("I"); //$NON-NLS-1$
			// IdentityProvider
			// Obtenim l'instància
			IdentityProviderEntity idp = (IdentityProviderEntity) source;
			// Heretats de VIP
			target.setPublicId(idp.getPublicId());
			target.setPublicKey(idp.getPublicKey());
			target.setPrivateKey(idp.getPrivateKey());
			target.setCertificateChain(idp.getCertificateChain());
			// Propis
			target.setInternal(idp.isInternal());
			target.setHostName(idp.getHostName());
			target.setStandardPort(idp.getStandardPort());
			target.setClientCertificatePort(idp.getClientCertificatePort());
			target.setDisableSSL(idp.getDisableSSL());
			
			
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

		} else if (source instanceof ServiceProviderEntity) {
			target.setClasse("S"); //$NON-NLS-1$
			// ServiceProvicer
			// Obtenim l'instància
			ServiceProviderEntity sp = (ServiceProviderEntity) source;
			// Heretats de VIP
			target.setPublicId(sp.getPublicId());
			target.setNameIdFormat(sp.getNameIdFormat());
			target.setCertificateChain(sp.getCertificateChain());
			
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
		}

	}

	private void generateRegisterValues(
			com.soffid.iam.addons.federation.common.FederationMember target,
			VirtualIdentityProviderEntity vip) {
		target.setAllowCertificate(vip.isAllowCertificate());
		target.setAllowRecover(vip.isAllowRecover());
		target.setAllowRegister(vip.isAllowRegister());
		target.setUserTypeToRegister(vip.getUserTypeToRegister() == null? null :
			vip.getUserTypeToRegister().getCodi());
		target.setGroupToRegister(vip.getGroupToRegister() == null? null: vip.getGroupToRegister().getCodi());
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
			idp.setPublicId(source.getPublicId());
			idp.setPublicKey(source.getPublicKey());
			idp.setPrivateKey(source.getPrivateKey());
			if (source.getCertificateChain() != null)
				idp.setCertificateChain(source.getCertificateChain());
			// Propis
			if (source.getInternal() != null)
				idp.setInternal(source.getInternal());
			idp.setHostName(source.getHostName());
			idp.setStandardPort(source.getStandardPort());
			idp.setClientCertificatePort(source.getClientCertificatePort());
			idp.setDisableSSL(source.getDisableSSL());
			
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
			sp.setPublicId(source.getPublicId());
			sp.setNameIdFormat(source.getNameIdFormat());
			if (source.getCertificateChain() != null)
				sp.setCertificateChain(source.getCertificateChain());
			
			// Aquí no guardem la relació SP-VIP (ServiceProviderVirtualIdentityProviderEntity)
			
			target = sp;
		}

	}

	private void updateRegisterAttributes(
			com.soffid.iam.addons.federation.common.FederationMember source,
			VirtualIdentityProviderEntity vip)  {
		vip.setAllowCertificate(source.isAllowCertificate());
		vip.setAllowRecover(source.isAllowRecover());
		vip.setAllowRegister(source.isAllowRegister());
		vip.setMailHost(source.getMailHost());
		vip.setMailSenderAddress(source.getMailSenderAddress());
		if (source.getUserTypeToRegister() == null)
		{
			vip.setUserTypeToRegister(null);
		}
		else
		{
			TipusUsuariEntity tipus = getTipusUsuariEntityDao().findByCodi(source.getUserTypeToRegister());
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
			GrupEntity grup = getGrupEntityDao().findByCodi(source.getGroupToRegister());
			if (grup == null)
				throw new IllegalArgumentException(String.format("Invalid group %s", source.getGroupToRegister()));
			vip.setGroupToRegister(grup);
		}
	}

}