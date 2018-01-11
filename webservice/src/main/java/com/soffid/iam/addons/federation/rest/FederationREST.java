package com.soffid.iam.addons.federation.rest;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.FederationServiceLocator;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.SamlRequest;

import es.caib.seycon.ng.exception.InternalErrorException;

@Path("/federation/rest")
@Produces({"application/rest+json", "application/json"})
@Consumes({"application/rest+json", "application/json"})
@ServletSecurity(@HttpConstraint(rolesAllowed = {"federation:query"}))
public class FederationREST {

	@Path("/validate-domain")
	@POST
	public Response validateDomain(RequestJSON request
			//@QueryParam("domain") @DefaultValue("") String domain
			) {

		try {

		// Parameter validation
		if (request.getDomain()==null || request.getDomain().trim().isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyDomain");

		// Domain validation
		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
		String idp = federationService.searchIdpForUser("dummy@"+request.getDomain());

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
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}

	@Path("/validate-credentials")
	@POST
	public Response validateCredentials(RequestJSON request)
//			@QueryParam("serviceProvider") @DefaultValue("") String serviceProviderName,
//			@QueryParam("identityProvider") @DefaultValue("") String identityProvider,
//			@QueryParam("user") @DefaultValue("") String user,
//			@QueryParam("password") @DefaultValue("") String password,
//			@QueryParam("sessionSeconds") @DefaultValue("3600") String sessionSeconds)
	{
		try {

		// Parameters validation
		if (request.getUser()==null || request.getUser().trim().isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyUser");
		if (request.getPassword()==null || request.getPassword().trim().isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyPassword");

		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
		SamlValidationResults r = federationService.authenticate(request.getServiceProviderName(), request.getIdentityProvider(), request.getUser(), request.getPassword(), Long.parseLong(request.getSessionSeconds()));
		return ResponseBuilder.responseOk(r);
		} catch (Exception e) {
			return ResponseBuilder.errorGeneric(e);
		}
	}
	
	@Path("/generate-saml-request")
	@POST
	public Response generateSAMLRequest(RequestJSON request)
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

	@Path("/parse-saml-response")
	@POST
	public Response parseSAMLResponse(RequestJSON request)
//			@QueryParam("autoProvision") Boolean autoProvision,
//			@QueryParam("response") Map<String, String> response,
//			@QueryParam("protocol") @DefaultValue("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") String protocol,
//			String serviceProviderName)
			
	{
		try {
		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
		//r = fs.authenticate("http://portal.arxus.com", "POST", map, false);
		LogFactory.getLog(getClass()).info(">>> Response = "+request.getResponse());
		SamlValidationResults r = federationService.authenticate(
				request.getServiceProviderName(),
				request.getProtocol(),
				request.getResponse(),
				request.getAutoProvision() == null ? false: request.getAutoProvision().booleanValue());
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

	public static void main (String [ ] args) {
		String pattern = "(aaa.com)|(bbb)";
		String userName = "aaa";
		boolean result = Pattern.matches("^"+pattern+"$", userName);
		//System.out.println(result);
		
		Map<String, String> map = new HashMap<String, String>();
		map.put("aaa", "bbb");
		map.put("111", "222");
		System.out.println(map);
	}
}
