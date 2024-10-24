//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.iam.addons.federation.model.EntityGroupEntity;
import com.soffid.mda.annotation.*;

@ValueObject 
@JsonObject(hibernateClass = EntityGroupEntity.class)
public class EntityGroup {

	@Nullable
	public java.lang.Long id;

	public java.lang.String name;

	@Nullable
	public java.lang.String metadataUrl;

	@Nullable
	public java.util.Collection members;

}
