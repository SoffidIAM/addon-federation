//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="TACACS" )
@Depends ({com.soffid.iam.addons.federation.model.FederationMemberEntity.class,
	com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity.class})
public abstract class TacacsProfileEntity extends ProfileEntity {
	@Column (name="PRO_AUTPOR")
	@Nullable
	Integer authPort;
	
	@Column (name="PRO_PAP")
	@Nullable
	Boolean pap;

	@Column (name="PRO_CHAP")
	@Nullable
	Boolean chap;

	@Column (name="PRO_ASCEE")
	@Nullable
	Boolean ascii;

	@Column (name="PRO_MSCHAP")
	@Nullable
	Boolean msChap;

	@Column (name="PRO_SSL")
	@Nullable
	Boolean ssl;

}
