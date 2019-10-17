package com.soffid.iam.addons.federation.model;

import java.util.Collection;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Index;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_USEBEH")
public class UserBehaviorEntity {
	@Column(name="UBE_ID")
	@Identifier Long id;
	
	@Column(name="UBE_USU_ID")
	Long userId;
	
	@Nullable
	@Column(name="UBE_KEY", length = 150)
	String key;
	
	@Nullable
	@Column(name="UBE_VALUE")
	String value;
	
	public Collection<UserBehaviorEntity> findByUserId(Long userId) { return null;}
	
	public UserBehaviorEntity findByUserIdAndKey(Long userId, String key) { return null;}
}

@Index(name = "SC_USEBEH_UK", entity = UserBehaviorEntity.class, columns = {"UBE_USU_ID", "UBE_KEY"}, unique = true)
class UserBehaviorEntityUniqueKey {}
