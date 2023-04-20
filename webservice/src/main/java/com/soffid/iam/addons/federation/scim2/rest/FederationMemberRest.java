package com.soffid.iam.addons.federation.scim2.rest;

import java.io.OutputStreamWriter;

import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.ws.rs.Consumes;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import org.json.JSONObject;

import com.soffid.iam.addon.scim2.json.JSONBuilder;
import com.soffid.iam.addon.scim2.rest.BaseRest;
import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;

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
		fm.setRegistrationToken(null);
		if ("S".equals(fm.getClasse())) {
			fm.setLoginHintScript(null);
			fm.setExtendedAuthenticationMethods(null);
		}
		if (!"S".equals(fm.getClasse()) ||
				(fm.getServiceProviderType() != ServiceProviderType.OPENID_CONNECT &&
				 fm.getServiceProviderType() != ServiceProviderType.OPENID_REGISTER)) {
			fm.setOpenidMechanism(null);
			fm.setAllowedScopes(null);
		}
		if (!"S".equals(fm.getClasse()) ||
				(fm.getServiceProviderType() != ServiceProviderType.CAS &&
				 fm.getServiceProviderType() != ServiceProviderType.OPENID_CONNECT &&
				 fm.getServiceProviderType() != ServiceProviderType.OPENID_REGISTER)) {
			fm.setOpenidLogoutUrl(null);
			fm.setOpenidUrl(null);
		}
		super.writeObject(w, builder, fm);
	}

	@Override
	protected FederationMember loadObject(JSONObject data) throws Exception {
		FederationMember fm = super.loadObject(data);
		if (data.has("registrationToken") && (data.get("registrationToken") instanceof String))
			fm.setRegistrationToken(new Digest(data.getString("registrationToken")));
		if (data.has("openidSecret") && (data.get("openidSecret") instanceof String))
			fm.setOpenidSecret(new Digest(data.getString("openidSecret")));
		return fm;
	}

	@Override
	public String[] jsonAttributesToIgnore() {
		return new String[] {"registrationToken", "openidSecret" };
	}
	
	

}

