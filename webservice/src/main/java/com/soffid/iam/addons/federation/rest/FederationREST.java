package com.soffid.iam.addons.federation.rest;

import java.rmi.RemoteException;
import java.util.Collection;
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
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.PasswordValidation;
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
			@QueryParam("user") @DefaultValue("") String user, 
			@QueryParam("password") @DefaultValue("") String password,
			@QueryParam("passwordDomain") @DefaultValue("") String passwordDomain)
			throws InternalErrorException {

		// Parameters validation
		if (user.isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyUser");
		if (password.isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyPassword");
		if (passwordDomain.isEmpty()) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "EmptyPasswordDomain");

		// User validation
		User portalUser = ServiceLocator.instance().getUserService().findUserByUserName(user);
		if (portalUser==null) return ResponseBuilder.errorCustom(Status.BAD_REQUEST, "UserNotFound");
				
		// Credential validation???
//		FederacioService federationService = FederationServiceLocator.instance().getFederacioService();
			
		// Account????
//		Collection<UserAccount> accounts = ServiceLocator.instance().getAccountService().getUserAccounts(portalUser);
//		for (UserAccount userAccount: accounts) {
//			userAccount.getName();
//		}
		
		// Auterization???
//		ServiceLocator.instance().getAuthorizationService();

		PasswordValidation result = null;
		try {
			// result = ServiceLocator.instance().getLogonService().validatePassword(user, password, passwordDomain);
			com.soffid.iam.sync.service.LogonService logonService = (LogonService) com.soffid.iam.ServiceLocator.instance().getContext().getBean("logonService-v2");
			result = logonService.validatePassword(user, password, passwordDomain);
		} catch (RemoteException e) {
			e.printStackTrace();
		}
		
		
		
		//ServiceLocator.instance().getPasswordService().checkPassword(arg0, arg1, arg2, arg3, arg4)
		// Response generation
//		if (idp == null) {
//			return ResponseBuilder.responseOk(new String("{\"exists\":\"no\",\"identityProvider\":\"\"}"));
//		} else {
//			return ResponseBuilder.responseOk(new String("{\"exists\":\"yes\",\"identityProvider\":\"" + idp + "\"}"));
//		}
		
		
		
		return ResponseBuilder.responseOk(result);
	}
	
	@Path("/generate-saml-request")
	@POST
	public Response generateSAMLRequest(@QueryParam("filter") @DefaultValue("") String filter, @QueryParam("attributes") String atts)
			throws InternalErrorException {
		return ResponseBuilder.responseOk(new String("{\"operation\":\"generate-saml-request\"}"));
	}

	@Path("/parse-saml-response")
	@POST
	public Response parseSAMLResponse(@QueryParam("filter") @DefaultValue("") String filter, @QueryParam("attributes") String atts)
			throws InternalErrorException {
		return ResponseBuilder.responseOk(new String("{\"operation\":\"parse-saml-response\"}"));
	}

	public static void main (String [ ] args) {
		String pattern = "(aaa.com)|(bbb)";
		String userName = "aaa";
		boolean result = Pattern.matches("^"+pattern+"$", userName);
		System.out.println(result);
	}
}
