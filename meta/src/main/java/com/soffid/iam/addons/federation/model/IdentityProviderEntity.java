//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="I" )
@Depends ({com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity.class})
public abstract class IdentityProviderEntity extends com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity {

	@Column (name="FED_INTERN",
		defaultValue="false")
	@Nullable
	public boolean internal;

	@ForeignKey (foreignColumn="FED_DFIP_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity> virtualIdentityProvider;

	@Column (name="FED_HOST",
		defaultValue="\"false\"")
	@Nullable
	public java.lang.String hostName;

	@Column (name="FED_STDPORT",
		defaultValue="\"false\"")
	@Nullable
	public java.lang.String standardPort;

	@Column (name="FED_CCERPORT",
		defaultValue="\"false\"")
	@Nullable
	public java.lang.String clientCertificatePort;
	
	@Column (name="FED_KTAB", length=1024)
	@Nullable
	public String ktabFile;

}
