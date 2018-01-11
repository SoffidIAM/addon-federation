package com.soffid.iam.addons.federation.rest;

import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.soffid.iam.addons.federation.FederationServiceLocator;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
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
@ServletSecurity(@HttpConstraint(rolesAllowed = { "federation:query" }))
public class FederationREST {

	@Path("/validate-domain")
	@POST
	public Response validateDomain(ValidateDomainJSONRequest request) {
		try {
			// Parameter validation
			if (request.getDomain() == null || request.getDomain().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyDomain");

			// Domain validation
			FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
			String idp = federationService.searchIdpForUser("dummy@" + request.getDomain());
			if (idp == null) {
				ValidateDomainJSONResponse response = new ValidateDomainJSONResponse();
				response.setExists("no");
				return ResponseBuilder.responseOk(response);
			} else {
				ValidateDomainJSONResponse response = new ValidateDomainJSONResponse();
				response.setExists("yes");
				response.setIdentityProvider(idp);
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
			FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
			SamlValidationResults r = federationService.authenticate(request.getServiceProviderName(),
					request.getIdentityProvider(), request.getUser(), request.getPassword(),
					Long.parseLong(request.getSessionSeconds()));
			return ResponseBuilder.responseOk(r);
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
			if (request.getUser() == null || request.getUser().trim().isEmpty())
				return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyUser");

			// Generate request
			FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
			SamlRequest r = federationService.generateSamlRequest(request.getServiceProviderName(),
					request.getIdentityProvider(), request.getUser(), Long.parseLong(request.getSessionSeconds()));
			return ResponseBuilder.responseOk(r);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
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
			FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
			SamlValidationResults r = federationService.authenticate(request.getServiceProviderName(),
					request.getProtocol(), request.getResponse(),
					request.getAutoProvision() == null ? false : request.getAutoProvision().booleanValue());
			return ResponseBuilder.responseOk(r);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

	@Path("/generate-saml-logout-request")
	@POST
	public Response generateSAMLLogoutRequest(RequestJSON request)
//			@QueryParam("serviceProvider") @DefaultValue("") String serviceProviderName,
//			@QueryParam("identityProvider") @DefaultValue("") String identityProvider,
//			@QueryParam("user") @DefaultValue("") String user,
//			@QueryParam("sessionSeconds") @DefaultValue("3600") String sessionSeconds)
	{
		try {
		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
		SamlRequest r = federationService.generateSamlRequest(request.getServiceProviderName(),
				request.getIdentityProvider(), request.getUser(), Long.parseLong(request.getSessionSeconds()));
		return ResponseBuilder.responseOk(r);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

}
