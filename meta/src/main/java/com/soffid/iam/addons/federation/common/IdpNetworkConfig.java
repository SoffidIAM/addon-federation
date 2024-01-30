package com.soffid.iam.addons.federation.common;

import com.soffid.iam.addons.federation.common.IdpNetworkEndpointType;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class IdpNetworkConfig {
	@Nullable @Identifier @Column(name = "INE_ID")
	Long id;
	
	@Column(name="INE_PROXY", defaultValue = "false")
	boolean proxy;
	
	@Nullable @Column(name="INE_PROPOR")
	Integer proxyPort;

	@Nullable @Column(name="INE_PROADR", length = 128)
	String proxyInternalAddress;

	@Column(name="INE_PORT", defaultValue = "443")
	int port;
	
	@Column(name="INE_TYPE", defaultValue = "com.soffid.iam.addons.federation.common.IdpNetworkEndpointType.TLSV_1_3")
	IdpNetworkEndpointType type;
	
	@Column(name="INE_WANCER", defaultValue = "true")
	boolean wantsCertificate;
	
	@Nullable @Column(name="INE_CERHEA")
	String certificateHeader;
	
	@Nullable @Column(name="INE_EXCPRO", length = 512)
	String excludedProtocols;
	
	@Column(name="INE_PROPRO", defaultValue = "false")
	boolean proxyProtocol;
	
}
