package com.soffid.iam.addons.federation.rest;

import java.util.Collection;

import javax.ejb.EJB;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.rest.json.ExpireSessionJSONRequest;
import com.soffid.iam.addons.federation.rest.json.GenerateSAMLLogoutRequestJSON;
import com.soffid.iam.addons.federation.rest.json.GenerateSAMLRequestJSONRequest;
import com.soffid.iam.addons.federation.rest.json.ParseSAMLResponseJSONRequest;
import com.soffid.iam.addons.federation.rest.json.ValidateCredentialsJSONRequest;
import com.soffid.iam.addons.federation.rest.json.ValidateDomainJSONRequest;
import com.soffid.iam.addons.federation.rest.json.ValidateDomainJSONResponse;
import com.soffid.iam.addons.federation.rest.response.ResponseBuilder;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.SamlRequest;

@Path("/federation/rest")
@Produces({ "application/rest+json", "application/json" })
@Consumes({ "application/rest+json", "application/json" })
public class FederationREST {
	@EJB 
	com.soffid.iam.addons.federation.service.ejb.FederacioService federationService;
	
	@Path("/validate-domain")
	@POST
	public Response validateDomain(ValidateDomainJSONRequest request) {
		try {
			// Parameter validation
			if (request.getDomain() == null || request.getDomain().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyDomain");

			// Domain validation
			String idp = federationService.searchIdpForUser("dummy@" + request.getDomain());
			if (idp == null) {
				ValidateDomainJSONResponse response = new ValidateDomainJSONResponse();
				response.setExists("no");
				return ResponseBuilder.responseOk(response);
			} else {
				ValidateDomainJSONResponse response = new ValidateDomainJSONResponse();
				response.setExists("yes");
				response.setIdentityProvider(idp);
				for (FederationMember fm: federationService.findFederationMemberByEntityGroupAndPublicIdAndTipus(null, idp, "I"))
				{
					response.setProtocol( fm.getIdpType() == IdentityProviderType.SAML || fm.getIdpType() == IdentityProviderType.SOFFID ? "SAML" : "OpenID-Connect");
				}
				return ResponseBuilder.responseOk(response);
			}
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

	@Path("/validate-credentials")
	@POST
	public Response validateCredentials(ValidateCredentialsJSONRequest request) {
		try {
			// Parameters validation
			if (request.getServiceProviderName() == null || request.getServiceProviderName().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyServiceProviderName");
			if (request.getIdentityProvider() == null || request.getIdentityProvider().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyIdentityProvider");
			if (request.getUser() == null || request.getUser().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyUser");
			if (request.getPassword() == null || request.getPassword().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyPassword");

			// Authentication validation
			SamlValidationResults r = federationService.authenticate(request.getServiceProviderName(),
					request.getIdentityProvider(), request.getUser(), request.getPassword(),
					Long.parseLong(request.getSessionSeconds()));
			return ResponseBuilder.responseOk(r);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

	@Path("/expire-session")
	@POST
	public Response expireSession(ExpireSessionJSONRequest request) {
		try {
			// Parameters validation
			if (request.getSessionId() == null || request.getSessionId().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptySessionId");

			// Authentication validation
			federationService.expireSessionCookie(request.getSessionId());
			return ResponseBuilder.responseOk(request);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

	@Path("/generate-saml-request")
	@POST
	public Response generateSAMLRequest(GenerateSAMLRequestJSONRequest request) {
		try {
			// Parameters validation
			if (request.getServiceProviderName() == null || request.getServiceProviderName().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyServiceProviderName");
			if (request.getIdentityProvider() == null || request.getIdentityProvider().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyIdentityProvider");

			// Generate request
			SamlRequest r = federationService.generateSamlRequest(request.getServiceProviderName(),
					request.getIdentityProvider(), request.getUser(), Long.parseLong(request.getSessionSeconds()));
			return ResponseBuilder.responseOk(r);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

	@Path("/generate-oidc-request")
	@POST
	public Response generateOIDCRequest(GenerateSAMLRequestJSONRequest request) {
		return generateSAMLRequest(request);
	}
	
	@Path("/parse-saml-response")
	@POST
	public Response parseSAMLResponse(ParseSAMLResponseJSONRequest request) {
		try {
			// Parameters validation
			if (request.getAutoProvision() == null)
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyAutoProvision");
			if (request.getResponse() == null || request.getResponse().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyResponse");
			if (request.getServiceProviderName() == null || request.getServiceProviderName().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyServiceProviderName");

			// Generate request
			SamlValidationResults r = federationService.authenticate(request.getServiceProviderName(),
					request.getProtocol(), request.getResponse(),
					request.getAutoProvision() == null ? false : request.getAutoProvision().booleanValue());
			return ResponseBuilder.responseOk(r);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

	@Path("/parse-oidc-response")
	@POST
	public Response parseODICResponse(ParseSAMLResponseJSONRequest request) {
		return parseSAMLResponse(request);
	}

	@Path("/generate-saml-logout-request")
	@POST
	public Response generateSAMLLogoutRequest(GenerateSAMLLogoutRequestJSON request)
	{
		try {
			// Parameters validation
			if (request.getServiceProviderName() == null || request.getServiceProviderName().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyServiceProviderName");
			if (request.getIdentityProvider() == null || request.getIdentityProvider().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyIdentityProvider");
			if (request.getUser() == null || request.getUser().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyUser");

			SamlRequest r = federationService.generateSamlLogoutRequest(request.getServiceProviderName(),
					request.getIdentityProvider(), request.getUser(),
					request.isForce(),
					request.isBackChannel());
			return ResponseBuilder.responseOk(r);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

}
