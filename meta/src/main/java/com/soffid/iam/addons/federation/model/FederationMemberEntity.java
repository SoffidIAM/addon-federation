//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
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
	com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity.class})
public abstract class FederationMemberEntity {

	@Column (name="FED_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="FED_NAME")
	@Nullable
	public java.lang.String name;

	@Column (name="FED_ORGAN")
	@Nullable
	public java.lang.String organization;

	@Column (name="FED_CONTAC")
	@Nullable
	public java.lang.String contact;

	@Column (name="FED_ENT_ID")
	public com.soffid.iam.addons.federation.model.EntityGroupEntity entityGroup;

	@Column (name="FED_META")
	@Nullable
	public byte[] metadades;

	@DaoFinder("select fm\nfrom\ncom.soffid.iam.addons.federation.model.FederationMemberEntity fm\nwhere\n(:entityGroupId is null or fm.entityGroup.id =:entityGroupId) \norder by fm.classe")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findByEntityGroupId(
		java.lang.Long entityGroupId) {
	 return null;
	}
	@DaoFinder("select fm\nfrom\ncom.soffid.iam.addons.federation.model.IdentityProviderEntity fm\nwhere\n(:entityGroupId is null or fm.entityGroup.id =:entityGroupId) ")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findIDPByEntityGroupId(
		java.lang.Long entityGroupId) {
	 return null;
	}
	@DaoFinder("select fm\nfrom\ncom.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity fm\nwhere\n(:entityGroupId is null or fm.entityGroup.id =:entityGroupId) \n")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findVIPByEntityGroupId(
		java.lang.Long entityGroupId) {
	 return null;
	}
	@DaoFinder("select fm\nfrom\ncom.soffid.iam.addons.federation.model.ServiceProviderEntity fm\nwhere\n(:entityGroupId is null or fm.entityGroup.id =:entityGroupId)")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findSPByEntityGroupId(
		java.lang.Long entityGroupId) {
	 return null;
	}
	@DaoFinder("select fm\nfrom\ncom.soffid.iam.addons.federation.model.IdentityProviderEntity fm\nwhere\n(fm.id=:id) ")
	public com.soffid.iam.addons.federation.model.IdentityProviderEntity findIDPById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select fm\nfrom\ncom.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity fm\nwhere\n(fm.id=:id) \n")
	public com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity findVIPById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select fm\nfrom\ncom.soffid.iam.addons.federation.model.ServiceProviderEntity fm\nwhere\n(fm.id=:id) ")
	public com.soffid.iam.addons.federation.model.ServiceProviderEntity findSPById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select fm\nfrom\ncom.soffid.iam.addons.federation.model.IdentityProviderEntity fm\nwhere\n(:tipusFM='I') and \n(:entityGroupName is null or fm.entityGroup.name like :entityGroupName)  and (:publicId is null or fm.publicId like :publicId)\nunion\nselect fm\nfrom\ncom.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity fm\nwhere\n(:tipusFM='V') and \n(:entityGroupName is null or fm.entityGroup.name like :entityGroupName)  and (:publicId is null or fm.publicId like :publicId)\nunion\nselect fm\nfrom\ncom.soffid.iam.addons.federation.model.ServiceProviderEntity fm\nwhere\n(:tipusFM='S') and \n(:entityGroupName is null or fm.entityGroup.name like :entityGroupName)  and (:publicId is null or fm.publicId like :publicId)")
	public java.util.List<com.soffid.iam.addons.federation.model.FederationMemberEntity> findFMByEntityGroupAndPublicIdAndTipus(
		java.lang.String entityGroupName, 
		java.lang.String publicId, 
		java.lang.String tipusFM) {
	 return null;
	}
}
