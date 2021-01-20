package com.soffid.iam.addons.federation.model;

import java.util.Collection;
import java.util.Date;

import com.soffid.iam.addons.federation.common.UserConsent;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Index;
import com.soffid.mda.annotation.Nullable;

import es.caib.seycon.ng.model.UsuariEntity;

@Entity(table = "SCF_USECON")
@Depends({UserConsent.class})
public class UserConsentEntity {
	@Column (name="UCO_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="UCO_USER", cascadeDelete = true)
	@Nullable
	Long userId;
	
	@Column(name="UCO_SERPRO")
	@Description("Service provider")
	String serviceProvider;
	
	@Column(name="UCO_DATE")
	Date date;
	
	@Column(name="UCO_TEN_ID")
	TenantEntity tenant;
	
	UserConsentEntity findByUserIdAndServiceProvider(Long userId, String serviceProvider) {return null;}
	
	Collection<UserConsentEntity> findByUserId(Long userId) {return null;}
}

@Index(entity = UserConsentEntity.class, columns = {"UCO_USER", "UCO_SERPRO"}, unique = true, name = "SCF_USECON_UK")
class UserContentUK {}
