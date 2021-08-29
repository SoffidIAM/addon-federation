//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

@Entity (table="SC_FEDERA" ,
		discriminatorValue="FM" ,
		discriminatorColumn="FED_CLASSE" )
@Depends ({es.caib.seycon.ng.model.TipusUsuariEntity.class,
	es.caib.seycon.ng.model.GrupEntity.class,
	com.soffid.iam.addons.federation.model.EntityGroupEntity.class,
	com.soffid.iam.addons.federation.common.FederationMember.class,
	com.soffid.iam.addons.federation.model.PolicyEntity.class,
	com.soffid.iam.addons.federation.model.SamlProfileEntity.class,
	com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity.class,
	AuthenticationMethodEntity.class,
	KerberosKeytabEntity.class})
public abstract class FederationMemberEntity {

	@Column (name="FED_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="FED_NAME")
	@Nullable
	public java.lang.String name;

	@Column (name="FED_INTERN",
			defaultValue="false")
	@Nullable
	public boolean internal;

	@Column (name="FED_PRIKEY", length=4000)
	@Nullable
	@Description("Conté la clau privada en format PEM")
	public java.lang.String privateKey;

	@Column (name="FED_PUBKEY", length=4000)
	@Nullable
	@Description("Conté la clau privada en format PEM")
	public java.lang.String publicKey;

	@Column (name="FED_CERCHA", length=8000)
	@Nullable
	@Description("Conté la cadena en format PEM amb el certificat propi i les autoritats de certificació")
	public java.lang.String certificateChain;

	@Column (name="FED_ORGAN")
	@Nullable
	public java.lang.String organization;

	@Column (name="FED_CONTAC")
	@Nullable
	public java.lang.String contact;

	
	@Column (name="FED_DISSSL", defaultValue="false")
	@Nullable
	public Boolean disableSSL;

	@Column (name="FED_HOST",
		defaultValue="\"false\"")
	@Nullable
	public java.lang.String hostName;

	@Column (name="FED_STDPORT",
		defaultValue="\"false\"")
	@Nullable
	public java.lang.String standardPort;

	@Description ("Identity Provider session timeout for oAuth sessions (in seconds)")
	@Nullable
	Long oauthSessionTimeout;

	
	@Column (name="FED_ENT_ID")
	public com.soffid.iam.addons.federation.model.EntityGroupEntity entityGroup;

	@Column (name="FED_META")
	@Nullable
	public byte[] metadades;

	@Column (name="FED_TEN_ID")
	public TenantEntity tenant;

	@Column (name="FED_ASSPAT")
	@Nullable
	public java.lang.String assertionPath;

	@Column (name="FED_DOMEXP")
	@Nullable
	public String domainExpression;

	@Column (name="FED_SCRPAR")
	@Nullable
	public String scriptParse;

	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.FederationMemberEntity fm "
			+ "where (:entityGroupId is null or fm.entityGroup.id =:entityGroupId) and "
			+ "eg.tenant.id=:tenantId "
			+ "order by fm.classe")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findByEntityGroupId(
		java.lang.Long entityGroupId) {
	 return null;
	}
	
	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.IdentityProviderEntity fm "
			+ "where (:entityGroupId is null or fm.entityGroup.id =:entityGroupId) and "
			+ "fm.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findIDPByEntityGroupId(
		java.lang.Long entityGroupId) {
	 return null;
	}
	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity fm "
			+ "where (:entityGroupId is null or fm.entityGroup.id =:entityGroupId) and "
			+ "fm.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findVIPByEntityGroupId(
		java.lang.Long entityGroupId) {
	 return null;
	}
	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.ServiceProviderEntity fm "
			+ "where (:entityGroupId is null or fm.entityGroup.id =:entityGroupId) and "
			+ "fm.tenant.id = :tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findSPByEntityGroupId(
		java.lang.Long entityGroupId) {
	 return null;
	}

	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.IdentityProviderEntity fm "
			+ "where (fm.id=:id) and fm.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.IdentityProviderEntity findIDPById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity fm "
			+ "where (fm.id=:id)  and fm.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity findVIPById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.ServiceProviderEntity fm "
			+ "where (fm.id=:id)  and fm.tenant.id=:tenantId")
	public com.soffid.iam.addons.federation.model.ServiceProviderEntity findSPById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.IdentityProviderEntity fm "
			+ "where (:tipusFM='I') and  "
			+ "(:entityGroupName is null or fm.entityGroup.name like :entityGroupName)  and "
			+ "(:publicId is null or fm.publicId like :publicId) and "
			+ "fm.tenant.id=:tenantId "
			+ "union "
			+ "select fm "
			+ "from com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity fm "
			+ "where (:tipusFM='V') and  "
			+ "(:entityGroupName is null or fm.entityGroup.name like :entityGroupName)  "
			+ "and (:publicId is null or fm.publicId like :publicId) and "
			+ "fm.tenant.id=:tenantId"
			+ "union "
			+ "select fm "
			+ "from com.soffid.iam.addons.federation.model.ServiceProviderEntity fm "
			+ "where (:tipusFM='S') and  "
			+ "(:entityGroupName is null or fm.entityGroup.name like :entityGroupName)  and "
			+ "(:publicId is null or fm.publicId like :publicId) and "
			+ "fm.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findFMByEntityGroupAndPublicIdAndTipus(
		java.lang.String entityGroupName, 
		java.lang.String publicId, 
		java.lang.String tipusFM) {
	 return null;
	}


	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.FederationMemberEntity fm "
			+ "where (fm.publicId = :publicId) and "
			+ "fm.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findFMByPublicId(
		java.lang.String publicId) {
	 return null;
	}

}

@Index( name="SC_FEDERA_UK", columns = {"FED_TEN_ID", "FED_NAME", "FED_CLASSE"}, unique = true, entity=FederationMemberEntity.class)
class FederationMembrEntityUK {}

@Index( name="SC_FEDERA_UK2", columns = {"FED_TEN_ID", "FED_PUBID"}, unique = true, entity=FederationMemberEntity.class)
class FederationMembrEntityUK2 {}
