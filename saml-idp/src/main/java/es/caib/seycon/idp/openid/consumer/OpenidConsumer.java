package es.caib.seycon.idp.openid.consumer;

import org.openid4java.association.AssociationException;
import org.openid4java.consumer.*;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.Identifier;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.*;
import org.openid4java.OpenIDException;

import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.openid.OpenIdResponseAction;
import es.caib.seycon.ng.exception.InternalErrorException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;

/**
 * Sample Consumer (Relying Party) implementation.
 */
public class OpenidConsumer implements Serializable {
	private static String yahooEndpoint = "https://me.yahoo.com";
	private static String googleEndpoint = "https://www.google.com";
	private static String googleEndpoint2 = "http://www.google.com";
	private static final String SESSION_ATTRIBUTE = "OpenidConsumer";

	public static OpenidConsumer fromSesssion(HttpSession session) {
		return (OpenidConsumer) session.getAttribute(SESSION_ATTRIBUTE);
	}

	public void store(HttpSession session) {
		session.setAttribute(SESSION_ATTRIBUTE, this);
	}
	
	

	public ConsumerManager manager;
	FederationMember fm;
	IdpConfig config;
	String relyingParty;
	
	public String getEmail() {
		return email;
	}

	public String getFullName() {
		return fullName;
	}

	public String getLastName() {
		return lastName;
	}

	public String getFirstName() {
		return firstName;
	}

	private String email;
	private String fullName;
	private String lastName;
	private String firstName;

	public OpenidConsumer(FederationMember fm) throws ConsumerException,
			UnrecoverableKeyException, InvalidKeyException,
			FileNotFoundException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException,
			InternalErrorException {
		// instantiate a ConsumerManager object
		manager = new ConsumerManager();
		this.fm = fm;
		config = IdpConfig.getConfig();
	}

	// --- placing the authentication request ---
	public String authRequest(String userSuppliedString,
			HttpServletRequest httpReq, HttpServletResponse httpResp)
			throws IOException, ServletException {
		relyingParty = userSuppliedString;
		try {
			// configure the return_to URL where your application will receive
			// the authentication responses from the OpenID provider

			String returnToUrl;
			if (config.getStandardPort() == 443)
				returnToUrl = "https://" + config.getHostName() 
				+ OpenIdResponseAction.URI;
			else
				returnToUrl = "https://" + config.getHostName() + ":"
					+ config.getStandardPort() + OpenIdResponseAction.URI;

			// --- Forward proxy setup (only if needed) ---
			// ProxyProperties proxyProps = new ProxyProperties();
			// proxyProps.setProxyName("proxy.example.com");
			// proxyProps.setProxyPort(8080);
			// HttpClientFactory.setProxyProperties(proxyProps);

			// perform discovery on the user-supplied identifier
			List discoveries = manager.discover(userSuppliedString);

			// attempt to associate with the OpenID provider
			// and retrieve one service endpoint for authentication
			DiscoveryInformation discovered = manager.associate(discoveries);

			// store the discovery information in the user's session
			httpReq.getSession().setAttribute("openid-disc", discovered);

			// obtain a AuthRequest message to be sent to the OpenID provider
			AuthRequest authReq = manager.authenticate(discovered, returnToUrl);

			// Attribute Exchange example: fetching the 'email' attribute
			FetchRequest fetch = FetchRequest.createFetchRequest();
			if (userSuppliedString.startsWith(googleEndpoint) ||
					userSuppliedString.startsWith(googleEndpoint2)) {
				fetch.addAttribute("email",
						"http://axschema.org/contact/email", true);
				fetch.addAttribute("firstName",
						"http://axschema.org/namePerson/first", true);
				fetch.addAttribute("lastName",
						"http://axschema.org/namePerson/last", true);
			} else if (userSuppliedString.startsWith(yahooEndpoint)) {
				fetch.addAttribute("email",
						"http://axschema.org/contact/email", true);
				fetch.addAttribute("fullname",
						"http://axschema.org/namePerson", true);
			} else { // works for myOpenID
				fetch.addAttribute("fullname",
						"http://schema.openid.net/namePerson", true);
				fetch.addAttribute("email",
						"http://schema.openid.net/contact/email", true);
			}

			authReq.addExtension(fetch);

			if (!discovered.isVersion2()) {
				// Option 1: GET HTTP-redirect to the OpenID Provider endpoint
				// The only method supported in OpenID 1.x
				// redirect-URL usually limited ~2048 bytes
				httpResp.sendRedirect(authReq.getDestinationUrl(true));
				return null;
			} else {
				generateForm(httpReq, httpResp, authReq);
			}
		} catch (OpenIDException e) {
			httpReq.setAttribute("ERROR", e.toString());
			// present error to the user
		}

		return null;
	}

	private void generateForm(HttpServletRequest httpReq,
			HttpServletResponse httpResp, AuthRequest authReq)
			throws IOException {
		httpResp.setContentType("text/html; encoding=utf-8");
		ServletOutputStream out = httpResp.getOutputStream();
		out.println("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"> ");
		out.println("<html xmlns='http://www.w3.org/1999/xhtml'>");
		out.println("<head>");
		out.println("<title>OpenID HTML FORM Redirection</title>");
		out.println("<script language='javascript'>\n"
				+"<!--\n"
				+"function submitOnce() {"
					+"if (location.hash.length>0) {"
						+"if (confirm(\"Are you sure you want to resubmit this form information a second time?\")) {"
							+"document.forms[0].submit();"
						+"} else {"
							+"document.body.innerHTML=\"<html>Form information was not resubmitted.</html>\";"
						+"}"
					+"} else {"
						+"var loc = window.location;"
						+"window.location = loc + \"#submitted\";"
						+"document.forms[0].submit();"
					+"}"
				+"}\n" 
				+"// -->\n"
				+"</script>");
		out.println("</head>");
		out.println("<body onload=\"submitOnce();\">");
		out.println("<noscript>");
		out.println("Press the continue button to login");
		out.println("</noscript>");
		out.print("<form name='openid-form-redirection' action='");
		out.print(authReq.getOPEndpoint());
		out.println("' method='post' accept-charset='utf-8'>");
		for (Object param : authReq.getParameterMap().keySet()) {
			Object value = authReq.getParameterMap().get(param);

			out.print("<input type='hidden' name='");
			out.print(param == null ? "" : param.toString());
			out.print("' value='");
			out.print(value == null ? "" : value.toString());
			out.print("'>");
		}
		out.println("<noscript>");
		out.println("<button type='submit'>Continue...</button>");
		out.println("</noscript>");
		out.println("</form>");
		out.println("</body>");
		out.println("</html>");
	}

	// --- processing the authentication response ---
	public Identifier verifyResponse(HttpServletRequest httpReq) throws MessageException, DiscoveryException, AssociationException {
		// extract the parameters from the authentication response
		// (which comes in as a HTTP request from the OpenID provider)
		ParameterList response = new ParameterList(httpReq.getParameterMap());

		// retrieve the previously stored discovery information
		DiscoveryInformation discovered = (DiscoveryInformation) httpReq
				.getSession().getAttribute("openid-disc");

		// extract the receiving URL from the HTTP request
		StringBuffer receivingURL = httpReq.getRequestURL();
		String queryString = httpReq.getQueryString();
		if (queryString != null && queryString.length() > 0)
			receivingURL.append("?").append(httpReq.getQueryString());

		// verify the response; ConsumerManager needs to be the same
		// (static) instance used to place the authentication request
		VerificationResult verification = manager.verify(
				receivingURL.toString(), response, discovered);

		// examine the verification result and extract the verified identifier
		Identifier verified = verification.getVerifiedId();
		if (verified != null) {
			AuthSuccess authSuccess = (AuthSuccess) verification
					.getAuthResponse();

			if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
				FetchResponse fetchResp = (FetchResponse) authSuccess
						.getExtension(AxMessage.OPENID_NS_AX);

				email = fetchResp.getAttributeValue("email");
				fullName = fetchResp.getAttributeValue("fullname");
				firstName = fetchResp.getAttributeValue("firstName");
				lastName = fetchResp.getAttributeValue("lastName");
			}

		}
		return verified; 
		
	}
	
	public String getRelyingParty()
	{
		return relyingParty;
	}
}
