package com.soffid.iam.addons.federation.model;

import java.util.Collection;
import java.util.Date;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
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
	
	@Column(name="UCR_SERIAL")
	String serialNumber;
	
	@Nullable
	@Column(name="UCR_DESCRI")
	String description;
	
	@Nullable
	@Column(name="UCR_RAWID", length = 512)
	String rawid;
	
	@Nullable
	@Column(name="UCR_KEY", length = 512)
	String key;
	
	@Nullable
	@Column(name="UCR_CREATED")
	Date created;
	
	@Nullable
	@Column(name="UCR_LASUSE")
	Date lastUse;

	public Collection<UserCredentialEntity> findByUserId(Long userId) { return null;}
	
	public UserCredentialEntity findBySerialNumber(String serialNumber) { return null;}
}

@Index(name = "SC_USECRE_UK", entity = UserCredentialEntity.class, columns = {"UCR_TEN_ID", "UCR_SERIAL"}, unique = true)
class UserCredentialEntityUniqueKey {}
