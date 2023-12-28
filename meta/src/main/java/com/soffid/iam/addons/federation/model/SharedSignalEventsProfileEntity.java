//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="SSE" )
public abstract class SharedSignalEventsProfileEntity extends 
	ProfileEntity {
	@Nullable @Column(name = "PRO_MAQUSI")
	Integer maxQueueSize;
}
