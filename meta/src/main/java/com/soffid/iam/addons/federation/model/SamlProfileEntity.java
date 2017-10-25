//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

@Entity (table="SC_SAMLPRO" ,
		discriminatorValue="SAMLPRO" ,
		discriminatorColumn="PRO_CLASSE" )
@Depends ({com.soffid.iam.addons.federation.common.SAMLProfile.class,
	com.soffid.iam.addons.federation.model.FederationMemberEntity.class,
	com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity.class})
public abstract class SamlProfileEntity {

	@Column (name="PRO_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="PRO_SGNRESP")
	@Nullable
	public java.lang.Long signResponses;

	@Column (name="PRO_SGNASSE")
	@Nullable
	public java.lang.Long signAssertions;

	@Column (name="PRO_SGNREQ")
	@Nullable
	public java.lang.Long signRequests;

	@Column (name="PRO_ENABLE")
	@Nullable
	public boolean enabled;

	@Column (name="PRO_VIP_ID")
	public com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity virtualIdentityProvider;
	
	@Column (name="PRO_TEN_ID")
	@Nullable
	public TenantEntity tenant;

	@DaoFinder("select en "
			+ "from com.soffid.iam.addons.federation.model.SamlProfileEntity en "
			+ "where (:virtualIPId is null or en.virtualIdentityProvider.id =:virtualIPId) and "
			+ "en.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.SamlProfileEntity> findByVIPId(
		java.lang.Long virtualIPId) {
	 return null;
	}
	@DaoFinder("select en  "
			+ "from  com.soffid.iam.addons.federation.model.Saml1ArtifactResolutionProfileEntity en "
			+ "where (:id is null or en.id =:id) and "
			+ "en.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.Saml1ArtifactResolutionProfileEntity findSAML1ARPById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select en  "
			+ "from  com.soffid.iam.addons.federation.model.Saml1AttributeQueryProfileEntity en "
			+ "where (:id is null or en.id =:id) and "
			+ "en.tenant.id=:tenantId ")
	public com.soffid.iam.addons.federation.model.Saml1AttributeQueryProfileEntity findSAML1AQPbyId(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select en "
			+ "from  com.soffid.iam.addons.federation.model.Saml2ArtifactResolutionProfileEntity en "
			+ "where (:id is null or en.id =:id) and "
			+ "en.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.Saml2ArtifactResolutionProfileEntity findSAML2ARPbyId(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select en  "
			+ "from  com.soffid.iam.addons.federation.model.Saml2AttributeQueryProfileEntity en "
			+ "where (:id is null or en.id =:id) and "
			+ "en.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.Saml2AttributeQueryProfileEntity findSAML2AQPbyId(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select en "
			+ "from com.soffid.iam.addons.federation.model.Saml2ECPProfileEntity en "
			+ "where (:id is null or en.id =:id) and "
			+ "en.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.Saml2ECPProfileEntity findSAML2ECPPbyId(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select en "
			+ "from com.soffid.iam.addons.federation.model.Saml2SSOProfileEntity en "
			+ "where (:id is null or en.id =:id) and "
			+ "en.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.Saml2SSOProfileEntity findSAML2SSOPbyId(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select en  "
			+ "from  com.soffid.iam.addons.federation.model.SamlProfileEntity en "
			+ "where (:id is null or en.id =:id) and "
			+ "en.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.SamlProfileEntity findSAMLProfileById(
		java.lang.Long id) {
	 return null;
	}
}
