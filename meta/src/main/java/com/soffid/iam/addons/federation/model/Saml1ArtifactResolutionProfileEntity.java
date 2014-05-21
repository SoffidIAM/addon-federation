//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="SAML1ARP" )
public abstract class Saml1ArtifactResolutionProfileEntity extends com.soffid.iam.addons.federation.model.SamlProfileEntity {

}
