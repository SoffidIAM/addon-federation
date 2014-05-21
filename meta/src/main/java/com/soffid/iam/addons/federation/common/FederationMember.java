//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public abstract class FederationMember {

	@Nullable
	public java.lang.Long id;

	public String classe;

	@Nullable
	public java.lang.String name;

	@Nullable
	public java.lang.String organization;

	@Nullable
	public java.lang.String contact;

	@Nullable
	public java.lang.String metadades;

	@Nullable
	public java.lang.String publicId;

	@Nullable
	public java.lang.String publicKey;

	@Nullable
	public java.lang.String privateKey;

	@Nullable
	public java.lang.String certificateChain;

	@Nullable
	public java.lang.String nameIdFormat;

	@Nullable
	public com.soffid.iam.addons.federation.common.EntityGroup entityGroup;

	@Nullable
	public java.util.Collection<com.soffid.iam.addons.federation.common.FederationMember> serviceProvider;

	@Nullable
	public java.util.Collection<com.soffid.iam.addons.federation.common.FederationMember> virtualIdentityProvider;

	@Nullable
	public com.soffid.iam.addons.federation.common.FederationMember defaultIdentityProvider;

	@Nullable
	public java.lang.Boolean internal;

	@Nullable
	public java.lang.String hostName;

	@Nullable
	public java.lang.String standardPort;

	@Nullable
	public java.lang.String clientCertificatePort;

	@Nullable
	public java.util.Collection<java.lang.String> virtualIdentityProviderPublicId;

	@Nullable
	public java.util.Collection<java.lang.String> serviceProviderPublicId;

	public boolean allowRegister;

	public boolean allowCertificate;

	public boolean allowRecover;

	@Nullable
	public java.lang.String userTypeToRegister;

	@Nullable
	public java.lang.String groupToRegister;

	@Nullable
	public java.lang.String mailHost;

	@Nullable
	public java.lang.String mailSenderAddress;

}
