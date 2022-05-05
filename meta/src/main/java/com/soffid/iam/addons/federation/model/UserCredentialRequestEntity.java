package com.soffid.iam.addons.federation.model;

import java.util.Collection;
import java.util.Date;

import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.DaoOperation;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Index;

@Entity(table="SC_USCRRE")
public class UserCredentialRequestEntity {
	@Column(name="UCQ_ID")
	@Identifier Long id;
	
	@Column(name="UCQ_USU_ID")
	Long userId;
	
	@Column(name="UCQ_TEN_ID")
	TenantEntity tenant;

	@Column(name="UCQ_HASH")
	String hash;
	
	@Column(name="UCQ_EXPIRE")
	Date expiration;
	
	UserCredentialRequestEntity findByHash(String hash) {return null;}
	
	@DaoOperation
	void deleteExpired () {}
}

@Index(entity = UserCredentialRequestEntity.class, columns = {"UCQ_HASH"}, name = "SC_USCRRE_UK", unique = true)
class UserCredentialRequestEntityUniqueKey {}