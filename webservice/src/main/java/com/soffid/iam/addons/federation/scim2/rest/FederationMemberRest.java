package com.soffid.iam.addons.federation.scim2.rest;

import java.io.OutputStreamWriter;

import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.ws.rs.Consumes;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import com.soffid.iam.addon.scim2.json.JSONBuilder;
import com.soffid.iam.addon.scim2.rest.BaseRest;
import com.soffid.iam.addons.federation.common.FederationMember;

@Path("/scim2/v1/FederationMember")
@Produces({"application/scim+json", "application/json"})
@Consumes({"application/scim+json", "application/json"})
@ServletSecurity(@HttpConstraint(rolesAllowed = {"scim:invoke"}))
public class FederationMemberRest extends BaseRest<FederationMember> {

	public FederationMemberRest() {
		super(FederationMember.class);
	}

	@Override
	public void writeObject(OutputStreamWriter w, JSONBuilder builder, FederationMember obj) {
		FederationMember fm = new FederationMember(obj);
		fm.setPrivateKey(null);
		fm.setSslPrivateKey(null);
		fm.setOpenidSecret(null);
		super.writeObject(w, builder, obj);
	}

}
