package com.soffid.iam.addons.federation.model;

import java.util.Collection;
import java.util.Date;
import java.util.List;

import com.soffid.iam.addons.federation.api.HostCredential;
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Index;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_HOSCRE")
@Depends({HostCredential.class})
public class HostCredentialEntity {
	@Column(name="HCR_ID")
	@Identifier Long id;
	
	@Column(name="HCR_MAQ_ID")
	Long hostId;
	
	@Column(name="HCR_TEN_ID")
	TenantEntity tenant;
	
	@Nullable
	@Column (name="HCR_TYPE", length=10)
	public UserCredentialType type;

	@Column(name="HCR_SERIAL")
	String serialNumber;
	
	@Nullable
	@Column(name="HCR_DESCRI")
	String description;
	
	@Nullable
	@Description("Fido token id")
	@Column(name="HCR_RAWID", length = 512)
	String rawid;
	
	@Nullable
	@Description("Public key for either FIDO token or digital certificates")
	@Column(name="HCR_KEY", length = 1024)
	String key;
	
	@Nullable
	@Description("Base 64 X509 certificate for digital certificates")
	@Column(name="HCR_CERT", length = 2048)
	String certificate;

	@Nullable
	@Column(name="HCR_CREATED")
	Date created;
	
	@Nullable
	@Column(name="HCR_LASUSE")
	Date lastUse;
	
	@Nullable
	@Column(name="HCR_FAILS")
	Integer fails;

	@Column (name="HCR_CAR_ID", reverseAttribute = "certificates")
	@Nullable
	public RootCertificateEntity root;

	@Column (name="HCR_EXPDAT")
	@Nullable
	public java.util.Date expirationDate;


	public Collection<HostCredentialEntity> findByHostId(Long hostId) { return null;}
	
	public List<HostCredentialEntity> findBySerialNumber(String serialNumber) { return null;}

	public List<HostCredentialEntity> findByPublicKey(String key) { return null;}
}

@Index(name = "SC_HOSCRE_UK", entity = HostCredentialEntity.class, columns = {"HCR_TEN_ID", "HCR_SERIAL"})
class HostCredentialEntityUniqueKey {}
