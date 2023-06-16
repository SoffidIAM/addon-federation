package com.soffid.iam.addons.federation.model;

import java.util.Collection;
import java.util.Date;
import java.util.List;

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

@Entity(table = "SC_USECRE")
@Depends({UserCredential.class})
public class UserCredentialEntity {
	@Column(name="UCR_ID")
	@Identifier Long id;
	
	@Column(name="UCR_USU_ID")
	Long userId;
	
	@Column(name="UCR_TEN_ID")
	TenantEntity tenant;
	
	@Nullable
	@Column (name="UCR_TYPE", length=10)
	public UserCredentialType type;

	@Column(name="UCR_SERIAL")
	String serialNumber;
	
	@Nullable
	@Column(name="UCR_DESCRI")
	String description;
	
	@Nullable
	@Description("Fido token id")
	@Column(name="UCR_RAWID", length = 512)
	String rawid;
	
	@Nullable
	@Description("Public key for either FIDO token or digital certificates")
	@Column(name="UCR_KEY", length = 512)
	String key;
	
	@Nullable
	@Description("Base 64 X509 certificate for digital certificates")
	@Column(name="UCR_CERT", length = 2048)
	String certificate;

	@Nullable
	@Column(name="UCR_CREATED")
	Date created;
	
	@Nullable
	@Column(name="UCR_LASUSE")
	Date lastUse;
	
	@Nullable
	@Column(name="UCR_FAILS")
	Integer fails;

	@Column (name="UCR_CAR_ID", reverseAttribute = "certificates")
	@Nullable
	public RootCertificateEntity root;

	@Column (name="UCR_EXPDAT")
	@Nullable
	public java.util.Date expirationDate;


	public Collection<UserCredentialEntity> findByUserId(Long userId) { return null;}
	
	public List<UserCredentialEntity> findBySerialNumber(String serialNumber) { return null;}

	public List<UserCredentialEntity> findByPublicKey(String key) { return null;}
}

@Index(name = "SC_USECRE_UK", entity = UserCredentialEntity.class, columns = {"UCR_TEN_ID", "UCR_SERIAL"})
class UserCredentialEntityUniqueKey {}
