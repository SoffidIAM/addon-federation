package com.soffid.iam.addons.federation.test;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.soffid.iam.addons.federation.FederationServiceLocator;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.model.SamlRequestEntity;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class SAMLClientTest {
	public static void main(String args[]) throws Exception {
		InitializationService.initialize();
		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
		// Get the assertion builder based on the assertion element name
		SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);

		EntityDescriptor idp = getIdpMetadata();
		if (idp == null)
			throw new InternalErrorException(String.format("Unable to find Identity Provider metadata"));
		IDPSSODescriptor idpssoDescriptor = idp.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);

		EntityDescriptor sp = getSpMetadata();
		
		// Create the assertion
		AuthnRequest req = builder.buildObject( );
		
		String newID = generateRandomId();
		
		SamlRequest r = new SamlRequest();
		r.setParameters(new HashMap<String, String>());
		SPSSODescriptor spsso = sp.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
		if (spsso == null)
			throw new InternalErrorException("Unable to find SP SSO Profile ");
		boolean found = false;
		for ( AssertionConsumerService acs : spsso.getAssertionConsumerServices())
		{
			if (acs.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI))
			{
				req.setAssertionConsumerServiceURL(acs.getLocation());
				req.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
			}
		}
		if (req.getAssertionConsumerServiceURL() == null)
			throw new InternalErrorException("Unable to find a HTTP-Post binding for SP");

		req.setForceAuthn(false);
		req.setID(newID);
		req.setIssueInstant(new DateTime ());
		Issuer issuer = ( (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
		issuer.setValue( sp.getEntityID() );
		
		req.setIssuer( issuer );

		for (SingleSignOnService sss : idpssoDescriptor.getSingleSignOnServices()) {
			if (sss.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) { // Max GET length is usually 8192
				r.setMethod(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
				r.setUrl(sss.getLocation());
				req.setDestination(sss.getLocation());
				break;
			}
		}
		
		NameIDPolicy policy = ( (SAMLObjectBuilder<NameIDPolicy>)builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME)).buildObject();
		policy.setFormat(NameID.TRANSIENT);
//		policy.setFormat(NameID.PERSISTENT);
		
		req.setNameIDPolicy(policy);
		
		if (r.getUrl() == null)
			throw new InternalErrorException(String.format("Unable to find a suitable endpoint for IdP %s"), idp.getEntityID());

		MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(req);
		Element xml = marshaller.marshall(req);

		
		String xmlString = generateString(xml);
		System.out.println(xmlString);
		
		

		// Encode base 64
		String encodedRequest = Base64.encodeBytes(xmlString.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
		r.getParameters().put("SAMLRequest", encodedRequest);
		r.getParameters().put("RelayState", newID);
		System.out.println(r.getUrl()+"?RelayState="+URLEncoder.encode(newID)+"&SAMLRequest="+URLEncoder.encode(encodedRequest));
	}

	private static EntityDescriptor getIdpMetadata() throws Exception {
		String metadata = "<EntityDescriptor entityID=\"test-idp3\"\n"
				+ "                  xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"\n"
				+ "                  xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"\n"
				+ "                  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n"
				+ "\n"
				+ "    <IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol\">\n"
				+ "\n"
				+ "        <KeyDescriptor>\n"
				+ "            <ds:KeyInfo>\n"
				+ "                <ds:X509Data>\n"
				+ "                    <ds:X509Certificate>\n"
				+ "MIIC+jCCAeKgAwIBAgIGAXZQq25LMA0GCSqGSIb3DQEBBQUAMD4xGDAWBgNVBAMMD3NvZmZpZC5i\n"
				+ "dWJ1LmxhYjERMA8GA1UECwwIU0FNTC1JRFAxDzANBgNVBAoMBlNvZmZpZDAeFw0yMDEyMTEwNzE5\n"
				+ "NDBaFw0yNTEyMTAwNzE5NDBaMD4xGDAWBgNVBAMMD3NvZmZpZC5idWJ1LmxhYjERMA8GA1UECwwI\n"
				+ "U0FNTC1JRFAxDzANBgNVBAoMBlNvZmZpZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
				+ "ALryb0vwge8OY281LS4fQfAUwOMn/nDiKNph69j4X00PZjeHwBVQuWQn9iFD23aR9SZM8UDW9lwg\n"
				+ "pFYUiPSktsHwlIPLqTD7S8ot85xDQxFnyTiH9VY6EQAhQU4vIdSuq16QOaqT2Mk54wfrwCHvxV9n\n"
				+ "bvGns4sJcdPkEtg+DvNgHybINRh31UGpfSCCm52q2GR2bBALK4Ga8K1bhRQKaV7GaNz7Xo2+wnas\n"
				+ "BIM91cjsiMW6lDx5UKXERnc6b3LZbwVFtHh7O7MfyhFgFXv3yPrmKkpbeHqixLHmuzTONRRljY4b\n"
				+ "o7paNDgPmelvCxXezNM2qS3KgZHTFUnhbjeTD50CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAaADX\n"
				+ "GTGmNdKVga6eapTN21qhJMClVdcY5W3jX3FZXzjIzBgKE77nicCXuI8RRnEn26r6uPaWi27BReVO\n"
				+ "XZw4aKKssA1f7uee/1IDPCMjNztAZcMK/PjUQekbnpHn85L3CiowjvslhRqfORpyU27aCD2yD90q\n"
				+ "6wLWB6CH0wRzPNRIa1COe4v1+TOzhP+eS/yZxTXH+eOe8rVJs/HIVnEODqICcRgdrPi2bPAJqcDW\n"
				+ "9c8xDd16qMAkw99BGYyZ33hET4V7YCAXKZg0Bafl5wUhzLVuRJoertOlHgzd3jCjXXPZN8kjJCYu\n"
				+ "xlvuQZf/Tzoy1UkWmzVKxDv6KePdv22vRw==\n"
				+ "                    </ds:X509Certificate>\n"
				+ "                </ds:X509Data>\n"
				+ "            </ds:KeyInfo>\n"
				+ "        </KeyDescriptor>\n"
				+ "        \n"
				+ "        <ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding\"\n"
				+ "                                   Location=\"https://soffid.bubu.lab:5443/profile/SAML1/SOAP/ArtifactResolution\" \n"
				+ "                                   index=\"1\"/>\n"
				+ "\n"
				+ "        <ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\"\n"
				+ "                                   Location=\"https://soffid.bubu.lab:5443/profile/SAML2/SOAP/ArtifactResolution\" \n"
				+ "                                   index=\"2\"/>\n"
				+ "                                   \n"
				+ " 		<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://soffid.bubu.lab:5443/profile/SAML2/Redirect/SLO\" />\n"
				+ "\n"
				+ "        <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://soffid.bubu.lab:5443/profile/SAML2/POST/SLO\" />\n"
				+ "\n"
				+ "        <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"https://soffid.bubu.lab:5443/profile/SAML2/SOAP/SLO\" />\n"
				+ " \n"
				+ "		<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>\n"
				+ "        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>\n"
				+ "        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>\n"
				+ "\n"
				+ "        <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" \n"
				+ "                             Location=\"https://soffid.bubu.lab:5443/profile/SAML2/Redirect/SSO\" />\n"
				+ "\n"
				+ "        <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \n"
				+ "                             Location=\"https://soffid.bubu.lab:5443/profile/SAML2/POST/SSO\" />\n"
				+ "\n"
				+ "	<SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign\"\n"
				+ "                             Location=\"https://soffid.bubu.lab:5443/profile/SAML2/POST-SimpleSign/SSO\" />\n"
				+ "\n"
				+ "    </IDPSSODescriptor>\n"
				+ "\n"
				+ "	<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n"
				+ "		<KeyDescriptor>\n"
				+ "			<ds:KeyInfo>\n"
				+ "				<ds:X509Data>\n"
				+ "					<ds:X509Certificate>\n"
				+ "MIIC+jCCAeKgAwIBAgIGAXZQq25LMA0GCSqGSIb3DQEBBQUAMD4xGDAWBgNVBAMMD3NvZmZpZC5i\n"
				+ "dWJ1LmxhYjERMA8GA1UECwwIU0FNTC1JRFAxDzANBgNVBAoMBlNvZmZpZDAeFw0yMDEyMTEwNzE5\n"
				+ "NDBaFw0yNTEyMTAwNzE5NDBaMD4xGDAWBgNVBAMMD3NvZmZpZC5idWJ1LmxhYjERMA8GA1UECwwI\n"
				+ "U0FNTC1JRFAxDzANBgNVBAoMBlNvZmZpZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
				+ "ALryb0vwge8OY281LS4fQfAUwOMn/nDiKNph69j4X00PZjeHwBVQuWQn9iFD23aR9SZM8UDW9lwg\n"
				+ "pFYUiPSktsHwlIPLqTD7S8ot85xDQxFnyTiH9VY6EQAhQU4vIdSuq16QOaqT2Mk54wfrwCHvxV9n\n"
				+ "bvGns4sJcdPkEtg+DvNgHybINRh31UGpfSCCm52q2GR2bBALK4Ga8K1bhRQKaV7GaNz7Xo2+wnas\n"
				+ "BIM91cjsiMW6lDx5UKXERnc6b3LZbwVFtHh7O7MfyhFgFXv3yPrmKkpbeHqixLHmuzTONRRljY4b\n"
				+ "o7paNDgPmelvCxXezNM2qS3KgZHTFUnhbjeTD50CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAaADX\n"
				+ "GTGmNdKVga6eapTN21qhJMClVdcY5W3jX3FZXzjIzBgKE77nicCXuI8RRnEn26r6uPaWi27BReVO\n"
				+ "XZw4aKKssA1f7uee/1IDPCMjNztAZcMK/PjUQekbnpHn85L3CiowjvslhRqfORpyU27aCD2yD90q\n"
				+ "6wLWB6CH0wRzPNRIa1COe4v1+TOzhP+eS/yZxTXH+eOe8rVJs/HIVnEODqICcRgdrPi2bPAJqcDW\n"
				+ "9c8xDd16qMAkw99BGYyZ33hET4V7YCAXKZg0Bafl5wUhzLVuRJoertOlHgzd3jCjXXPZN8kjJCYu\n"
				+ "xlvuQZf/Tzoy1UkWmzVKxDv6KePdv22vRw==\n"
				+ "					</ds:X509Certificate>\n"
				+ "				</ds:X509Data>\n"
				+ "			</ds:KeyInfo>\n"
				+ "		</KeyDescriptor>\n"
				+ "		<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>\n"
				+ "		<AssertionConsumerService index=\"1\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n"
				+ "			Location=\"https://soffid.bubu.lab:5443/sp-profile/SAML2/POST/SSO\">\n"
				+ "		</AssertionConsumerService>\n"
				+ "	</SPSSODescriptor>\n"
				+ "\n"
				+ "    <AttributeAuthorityDescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol\">\n"
				+ "\n"
				+ "        <KeyDescriptor>\n"
				+ "            <ds:KeyInfo>\n"
				+ "                <ds:X509Data>\n"
				+ "                    <ds:X509Certificate>\n"
				+ "MIIC+jCCAeKgAwIBAgIGAXZQq25LMA0GCSqGSIb3DQEBBQUAMD4xGDAWBgNVBAMMD3NvZmZpZC5i\n"
				+ "dWJ1LmxhYjERMA8GA1UECwwIU0FNTC1JRFAxDzANBgNVBAoMBlNvZmZpZDAeFw0yMDEyMTEwNzE5\n"
				+ "NDBaFw0yNTEyMTAwNzE5NDBaMD4xGDAWBgNVBAMMD3NvZmZpZC5idWJ1LmxhYjERMA8GA1UECwwI\n"
				+ "U0FNTC1JRFAxDzANBgNVBAoMBlNvZmZpZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
				+ "ALryb0vwge8OY281LS4fQfAUwOMn/nDiKNph69j4X00PZjeHwBVQuWQn9iFD23aR9SZM8UDW9lwg\n"
				+ "pFYUiPSktsHwlIPLqTD7S8ot85xDQxFnyTiH9VY6EQAhQU4vIdSuq16QOaqT2Mk54wfrwCHvxV9n\n"
				+ "bvGns4sJcdPkEtg+DvNgHybINRh31UGpfSCCm52q2GR2bBALK4Ga8K1bhRQKaV7GaNz7Xo2+wnas\n"
				+ "BIM91cjsiMW6lDx5UKXERnc6b3LZbwVFtHh7O7MfyhFgFXv3yPrmKkpbeHqixLHmuzTONRRljY4b\n"
				+ "o7paNDgPmelvCxXezNM2qS3KgZHTFUnhbjeTD50CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAaADX\n"
				+ "GTGmNdKVga6eapTN21qhJMClVdcY5W3jX3FZXzjIzBgKE77nicCXuI8RRnEn26r6uPaWi27BReVO\n"
				+ "XZw4aKKssA1f7uee/1IDPCMjNztAZcMK/PjUQekbnpHn85L3CiowjvslhRqfORpyU27aCD2yD90q\n"
				+ "6wLWB6CH0wRzPNRIa1COe4v1+TOzhP+eS/yZxTXH+eOe8rVJs/HIVnEODqICcRgdrPi2bPAJqcDW\n"
				+ "9c8xDd16qMAkw99BGYyZ33hET4V7YCAXKZg0Bafl5wUhzLVuRJoertOlHgzd3jCjXXPZN8kjJCYu\n"
				+ "xlvuQZf/Tzoy1UkWmzVKxDv6KePdv22vRw==\n"
				+ "                    </ds:X509Certificate>\n"
				+ "                </ds:X509Data>\n"
				+ "            </ds:KeyInfo>\n"
				+ "        </KeyDescriptor>\n"
				+ "\n"
				+ "        <AttributeService Binding=\"urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding\" \n"
				+ "                          Location=\"https://soffid.bubu.lab:5443/profile/SAML1/SOAP/AttributeQuery\" />\n"
				+ "        \n"
				+ "        <AttributeService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\"\n"
				+ "                          Location=\"https://soffid.bubu.lab:5443/profile/SAML2/SOAP/AttributeQuery\" />\n"
				+ "        \n"
				+ "        <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>\n"
				+ "        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>\n"
				+ "        \n"
				+ "    </AttributeAuthorityDescriptor>\n"
				+ "    \n"
				+ "	<Organization>\n"
				+ "		<OrganizationName xml:lang=\"neutral\">Soffid</OrganizationName>\n"
				+ "		<OrganizationDisplayName xml:lang=\"neutral\">Soffid</OrganizationDisplayName>\n"
				+ "		<OrganizationURL xml:lang=\"neutral\">https://www.soffid.com</OrganizationURL>\n"
				+ "	</Organization>\n"
				+ "	<ContactPerson contactType=\"technical\">\n"
				+ "		<Company>Soffid</Company>\n"
				+ "		<EmailAddress>gbuades@soffid.com</EmailAddress>\n"
				+ "	</ContactPerson>\n"
				+ "\n"
				+ "</EntityDescriptor>    \n"
				+ "";

		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		dbFactory.setValidating(false);
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(new ByteArrayInputStream(metadata.getBytes(StandardCharsets.UTF_8)));

		UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();

		XMLObject ed = unmarshallerFactory.getUnmarshaller(EntityDescriptor.ELEMENT_QNAME)
				.unmarshall(doc.getDocumentElement());
		return (EntityDescriptor) ed;
	}

	private static EntityDescriptor getSpMetadata() throws Exception {
		String metadata = "<EntityDescriptor entityID=\"samltest\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n"
				+ "\n"
				+ "<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n"
				+ "\n"
				+ "<AssertionConsumerService index=\"1\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n"
				+ "Location=\"https://localhost/test\" >\n"
				+ "</AssertionConsumerService>\n"
				+ "\n"
				+ "</SPSSODescriptor>\n"
				+ "\n"
				+ "</EntityDescriptor>\n"
				+ "";
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		dbFactory.setValidating(false);
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(new ByteArrayInputStream(metadata.getBytes(StandardCharsets.UTF_8)));

		UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();

		XMLObject ed = unmarshallerFactory.getUnmarshaller(EntityDescriptor.ELEMENT_QNAME)
				.unmarshall(doc.getDocumentElement());
		return (EntityDescriptor) ed;
	}

	public static String generateRandomId() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        Hex encoder = new Hex();
        final byte[] buf = new byte[24];
        random.nextBytes(buf);
        return "_" + StringUtils.newStringUsAscii(encoder.encode(buf));
	}

	protected static String generateString(Element xml)
			throws TransformerConfigurationException,
			TransformerFactoryConfigurationError, TransformerException {
		Transformer transformer = TransformerFactory.newInstance().newTransformer();

		StreamResult result = new StreamResult(new StringWriter());
		DOMSource source = new DOMSource(xml);
		transformer.transform(source, result);

		String xmlString = result.getWriter().toString();
		return xmlString;
	}
}
