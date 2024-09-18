//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="ESSO" )
public abstract class EssoProfileEntity extends com.soffid.iam.addons.federation.model.ProfileEntity {

	@Nullable @Column(name = "PRO_HONAFO")
	String hostnameFormat;
	
	@Nullable @Column(name = "PRO_MAIAGE")
	String mainAgent;
	
	@Nullable @Column(name = "PRO_ENCLSE")
	Boolean enableCloseSession;
	
	@Nullable @Column(name = "PRO_FOLOST")
	Boolean forceStartupLogin;
	
	@Nullable @Column(name = "PRO_KEEALI")
	Integer keepAlive;
	
	@Nullable @Column(name = "PRO_IDLTIM")
	Integer idleTimeout;
	
	@Nullable @Column(name = "PRO_SHAWKS")
	Boolean sharedWorkstation;
	
	@Column(name = "PRO_CREPRO")
	@Nullable Boolean windowsCredentialProvider;
	
	@Column(name = "PRO_LOCACC")
	@Nullable Boolean createLocalAccounts;
	
	@Column(name = "PRO_SHPRUS")
	@Nullable Boolean showPreviousUser;
	
	@Column(name = "PRO_OFFDET")
	@Nullable Boolean offlineDetector;
	
	@Column(name = "PRO_OFFDAY")
	@Nullable Integer offlineDays;
	
}