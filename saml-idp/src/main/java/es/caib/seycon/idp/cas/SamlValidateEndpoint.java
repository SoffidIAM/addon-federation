package es.caib.seycon.idp.cas;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.TimeZone;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dom4j.dom.DOMText;
import org.json.JSONObject;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Entity;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import com.fasterxml.jackson.databind.node.TextNode;
import com.soffid.iam.addons.federation.api.LevelOfAssuranceEnum;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.TokenHandler;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class SamlValidateEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());

	private boolean addAttributes;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		doPost(req, resp);
	}
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		try {
			ServletInputStream in = req.getInputStream();
			
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(in);
			
			XPath xpath = XPathFactory.newInstance().newXPath();
			Node node = (Node) xpath.compile("//urn:oasis:names:tc:SAML:1.0:protocol:AssertionArtifact")
					.evaluate(doc, XPathConstants.NODE);
			String ticket  = "";
			for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
				if (child instanceof Text) {
					ticket = ticket + ((Text)child).getData().trim();
				}
			}
			String format = req.getParameter("format");
			resp.setContentType("text/xml");

			resp.setCharacterEncoding("utf-8");
			final ServletOutputStream out = resp.getOutputStream();
			
			TokenHandler h = TokenHandler.instance();
			TokenInfo t = null;
			t = h.getToken(ticket);
			if (t == null) {
				failure(out, "INVALID_REQUEST", "Wrong service name");
				resp.setStatus(HttpServletResponse.SC_OK);
			} else {
				Map<String, Object> atts = new UserAttributesGenerator().generateAttributes(req.getServletContext(), t, false, false, true);

				success (out, t, atts);
				resp.setStatus(HttpServletResponse.SC_OK);
			}
		} catch (Exception e) {
			log.warn("Error checking for CAS ticket", e);
			try {
				failure(resp.getOutputStream(), "INTERNAL_ERROR", "Error processing request. See log file");
			} catch (Exception e1) {
				throw new ServletException(e);
			}
			resp.setStatus(HttpServletResponse.SC_OK);
		}
	}

	private void failure(ServletOutputStream out, String code, String description) throws TransformerConfigurationException, TransformerException, TransformerFactoryConfigurationError, IOException, ParserConfigurationException {
		Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		Element o3 = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope");
		doc.appendChild(o3);
		
		Element o2 = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Header");
		o3.appendChild(o2);
		
		o2 = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Body");
		o3.appendChild(o2);
		
		Element o1 = doc.createElementNS("urn:oasis:names:tc:SAML:1.0:protocol", "Response");
		o1.setAttribute("xmlns:saml", "urn:oasis:names:tc:SAML:1.0:assertion");
		o1.setAttribute("xmlns:samlp", "urn:oasis:names:tc:SAML:1.0:protocol");
		o1.setAttribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema");
		o1.setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
		o2.appendChild(o1);
		
		Element o11 = doc.createElementNS("urn:oasis:names:tc:SAML:1.0:protocol", "Status");
		o1.appendChild(o11);
		
		Element o111 = doc.createElementNS("urn:oasis:names:tc:SAML:1.0:protocol", "StatusCode");
		o111.setAttribute("Value",  "samlp:Failure");
		o11.appendChild(o111);
		
		
		TransformerFactory.newInstance()
			.newTransformer()
			.transform(new DOMSource(doc), new StreamResult(out));
	}
	
	private void success(ServletOutputStream out, TokenInfo t, Map<String, Object> atts) throws TransformerConfigurationException, TransformerException, TransformerFactoryConfigurationError, IOException, ParserConfigurationException, UnrecoverableKeyException, InvalidKeyException, DOMException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		String user = (String) atts.get("uid");
		
		SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-YYYY'T'HH:mm:ss'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String authenticationDate = sdf.format(t.getCreated());
		
		Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		Element o3 = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope");
		doc.appendChild(o3);
		
		Element o2 = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Header");
		o3.appendChild(o2);
		
		o2 = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Body");
		o3.appendChild(o2);
		
		Element o1 = doc.createElementNS("urn:oasis:names:tc:SAML:1.0:protocol", "Response");
		o1.setAttribute("xmlns:saml", "urn:oasis:names:tc:SAML:1.0:assertion");
		o1.setAttribute("xmlns:samlp", "urn:oasis:names:tc:SAML:1.0:protocol");
		o1.setAttribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema");
		o1.setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
		o1.setAttribute("IssueInstant", sdf.format(new Date()));
		o1.setAttribute("Recipient", t.getRequest().getFederationMember().getPublicId());
		o1.setAttribute("MajorVersion", "1");
		o1.setAttribute("MinorVersion", "1");
		o1.setAttribute("ResponseID", generateRandomString());
		o2.appendChild(o1);
		
		Element o11 = doc.createElementNS("urn:oasis:names:tc:SAML:1.0:protocol", "Status");
		o1.appendChild(o11);
		
		Element o111 = doc.createElementNS("urn:oasis:names:tc:SAML:1.0:protocol", "StatusCode");
		o111.setAttribute("Value",  "samlp:Success");
		o11.appendChild(o111);
		
		o11 = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "Assertion");
		o1.appendChild(o11);
		o11.setAttribute("AssertionID", generateRandomString());
		o11.setAttribute("IssueInstant", sdf.format(new Date()));
		o11.setAttribute("Issuer", IdpConfig.getConfig().getPublicId());
		o11.setAttribute("MajorVersion", "1");
		o11.setAttribute("MinorVersion", "1");
		
		Element ob = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "Conditions");
		ob.setAttribute("NotBefore", sdf.format(new Date()));
		ob.setAttribute("NotAfter", sdf.format(new Date( System.currentTimeMillis() + 5 * 60_000 )));
		o11.appendChild(ob);
		
		Element oc = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "AudienceRestrictionCondition");
		ob.appendChild(oc);
		
		Element od = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "Audience");
		oc.appendChild(od);
		od.appendChild(doc.createTextNode(t.getRequest().getFederationMember().getPublicId()));
		
		ob = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "AttributeStatement");
		o11.appendChild(ob);
		oc = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "Subject");
		ob.appendChild(oc);
		od = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "NameIdentifier");
		oc.appendChild(od);
		od.appendChild(doc.createTextNode(t.getUser()));
		
		od = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "SubjectConfirmation");
		oc.appendChild(od);
		
		Element oe = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
		od.appendChild(oe);
		oe.appendChild(doc.createTextNode("urn:oasis:names:tc:SAML:1.0:cm:artifact"));

		for ( Entry<String, Object> entry: atts.entrySet()) {
			String v = stringify ( entry.getValue() );
			if (v != null) {
				try {
					oc = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "Attribute");
					ob.appendChild(oc);
					oc.setAttribute("AttributeName", entry.getKey());
					oc.setAttribute("AttributeNamespace", "http://www.ja-syg.org/products/cas/");
					
					od = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "AttributeValue");
					oc.appendChild(od);
					od.appendChild(doc.createTextNode(v));
				} catch (Exception e) {
					// Cannot serialize
				}
			}
		}

		ob = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "AuthenticationStatement");
		ob.setAttribute("AuthenticationMethod", 
				t.getLoa() == LevelOfAssuranceEnum.LOW ?
						"http://eidas.europa.eu/LoA/low" :
				t.getLoa() == LevelOfAssuranceEnum.HIGH ?
						"http://eidas.europa.eu/LoA/high" :
				t.getLoa() == LevelOfAssuranceEnum.SUBSTANTIAL ?
						"http://eidas.europa.eu/LoA/low" :
							"http://eidas.europa.eu/LoA/undefined" );
		o11.appendChild(ob);
		oc = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "Subject");
		ob.appendChild(oc);
		od = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "NameIdentifier");
		oc.appendChild(od);
		od.appendChild(doc.createTextNode(t.getUser()));
		
		od = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "SubjectConfirmation");
		oc.appendChild(od);
		
		oe = doc.createElementNS("urn:ooasis:names:tc:SAML:1.0:assertion", "ConfirmationMethod");
		od.appendChild(oe);
		oe.appendChild(doc.createTextNode("urn:oasis:names:tc:SAML:1.0:cm:artifact"));

		
		TransformerFactory.newInstance()
			.newTransformer()
			.transform(new DOMSource(doc), new StreamResult(out));
		
	}

	private String generateRandomString() {
		byte b[] = new byte[12];
		new Random().nextBytes(b);
		return "_"+java.util.Base64.getUrlEncoder().encodeToString(b);
	}
	private String stringify(Object value) {
		if (value == null) return null;
		if (value instanceof Collection) {
			StringBuffer sb = new StringBuffer();
			for (Object v: (Collection) value) {
				if (v != null) {
					if (sb.length() > 0) sb.append(", ");
					sb.append(v.toString());
				}
			}
		}
		return value.toString();
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
	}

}