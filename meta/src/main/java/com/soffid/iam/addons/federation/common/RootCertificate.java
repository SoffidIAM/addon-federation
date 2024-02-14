//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class RootCertificate {

	@Nullable
	public java.lang.Long id;

	public java.util.Calendar expirationDate;

	public boolean obsolete;

	public java.lang.String organizationName;

	@Nullable
	public java.lang.Integer userCertificateMonths;

	public java.util.Calendar creationDate;

	@Nullable
	public java.security.cert.X509Certificate certificate;

	boolean external;

	@Nullable
	public String guessUserScript;

	public boolean device;

	@Nullable
	public Integer expirationWarningDays;

	@Nullable
	Integer cacheDays;
}
