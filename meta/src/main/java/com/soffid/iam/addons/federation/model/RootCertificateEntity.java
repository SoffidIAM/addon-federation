//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.addons.federation.common.RootCertificate;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

@Entity (table="SCS_CAROOT" )
@Depends ({RootCertificate.class})
public abstract class RootCertificateEntity {

	@Column (name="CAR_CERTIF")
	public byte[] certificate;

	@Column (name="CAR_PRIKEY")
	@Nullable
	public byte[] privateKey;

	@Column (name="CAR_ID")
	@Nullable
	@Identifier
	public java.lang.Long id;

	@Column (name="CAR_EXPDAT")
	public java.util.Date expirationDate;

	@Column (name="CAR_OBSOLE")
	public boolean obsolete;

	@Column (name="CAR_ORGNAM")
	public java.lang.String organizationName;

	@Column (name="CAR_USCEMO")
	@Nullable
	public java.lang.Integer userCertificateMonths;

	@Column (name="CAR_CREDAT")
	public java.util.Date creationDate;

	@Column (name="CAR_EXTERN")
	public boolean external;

	@Nullable
	@Column (name="CAR_GUUSSC", length = 16000)
	public String guessUserScript;

	@Column(name="CAR_TEN_ID")
	TenantEntity tenant;
}
