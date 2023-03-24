package com.soffid.iam.addons.federation.scim2.rest;

import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.ws.rs.Consumes;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import com.soffid.iam.addon.scim2.rest.BaseRest;
import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.FederationMember;

@Path("/scim2/v1/EntityGroup")
@Produces({"application/scim+json", "application/json"})
@Consumes({"application/scim+json", "application/json"})
@ServletSecurity(@HttpConstraint(rolesAllowed = {"scim:invoke"}))
public class EntityGroupRest extends BaseRest<EntityGroup> {

	public EntityGroupRest() {
		super(EntityGroup.class);
	}

}

