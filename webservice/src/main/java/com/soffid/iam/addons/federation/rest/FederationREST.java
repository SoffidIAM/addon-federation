package com.soffid.iam.addons.federation.rest;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.FederationServiceLocator;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.sync.service.LogonService;

import es.caib.seycon.ng.exception.InternalErrorException;

@Path("/federation/rest")
@Produces({"application/rest+json", "application/json"})
@Consumes({"application/rest+json", "application/json"})
@ServletSecurity(@HttpConstraint(rolesAllowed = {"federation:query"}))
public class FederationREST {

	@Path("/validate-domain")
	@POST
	public Response validateDomain(@QueryParam("domain") @DefaultValue("") String domain) throws InternalErrorException {

		// Parameter validation
		if (domain.isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyDomain");

		// Domain validation
		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
		String idp = federationService.searchIdpForUser(domain);

		if (idp == null) {
			ValidateDomainJSON response = new ValidateDomainJSON();
			response.setExists("no");
			return ResponseBuilder.responseOk(response);
		} else {
			ValidateDomainJSON response = new ValidateDomainJSON();
			response.setExists("yes");
			response.setIdentityProvider(idp);
			return ResponseBuilder.responseOk(response);
		}
	}

	@Path("/validate-credentials")
	@POST
	public Response validateCredentials(
			@QueryParam("serviceProvider") @DefaultValue("") String serviceProviderName, 
			@QueryParam("identityProvider") @DefaultValue("") String identityProvider, 
			@QueryParam("user") @DefaultValue("") String user, 
			@QueryParam("password") @DefaultValue("") String password,
			@QueryParam("sessionSeconds") @DefaultValue("3600") String sessionSeconds)
			throws InternalErrorException {

		// Parameters validation
		if (user.isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyUser");
		if (password.isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyPassword");

		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
		SamlValidationResults r = federationService.authenticate(serviceProviderName, identityProvider, user, password, Long.parseLong(sessionSeconds));
		// User validation
		return ResponseBuilder.responseOk(r);
	}
	
	@Path("/generate-saml-request")
	@POST
	public Response generateSAMLRequest( 
			@QueryParam("serviceProvider") @DefaultValue("") String serviceProviderName, 
			@QueryParam("identityProvider") @DefaultValue("") String identityProvider, 
			@QueryParam("user") @DefaultValue("") String user, 
			@QueryParam("sessionSeconds") @DefaultValue("3600") String sessionSeconds)
			throws InternalErrorException {
		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
		SamlRequest r = federationService.generateSamlRequest(serviceProviderName, 
				identityProvider, user, Long.parseLong(sessionSeconds));
		// User validation
		return ResponseBuilder.responseOk(r);
	}

	@Path("/parse-saml-response")
	@POST
	public Response parseSAMLResponse(
			@QueryParam("autoProvision") Boolean autoProvision, 
			@QueryParam("response") Map<String, String> response, 
			@QueryParam("protocol") @DefaultValue("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") String protocol, 
			String serviceProviderName)
			throws InternalErrorException {

		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
		SamlValidationResults r = federationService.authenticate(serviceProviderName, 
				protocol, 
				response, 
				autoProvision == null ? false: autoProvision.booleanValue()) ;
		return ResponseBuilder.responseOk(r);
	}

	public static void main (String [ ] args) {
		String pattern = "(aaa.com)|(bbb)";
		String userName = "aaa";
		boolean result = Pattern.matches("^"+pattern+"$", userName);
		System.out.println(result);
	}
}
