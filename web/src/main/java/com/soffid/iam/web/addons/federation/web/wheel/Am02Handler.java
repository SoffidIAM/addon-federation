package com.soffid.iam.web.addons.federation.web.wheel;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.fileupload.FileUpload;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import org.zkoss.util.media.AMedia;
import org.zkoss.util.media.Media;
import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.UiException;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.UploadEvent;
import org.zkoss.zk.ui.ext.AfterCompose;
import org.zkoss.zul.Div;
import org.zkoss.zul.Filedownload;
import org.zkoss.zul.Html;
import org.zkoss.zul.Textbox;
import org.zkoss.zul.Window;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.AttributePolicyCondition;
import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.Policy;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.api.System;
import com.soffid.iam.service.ejb.DispatcherService;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.popup.Editor;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.signatura.utils.Base64;
import es.caib.zkib.component.Wizard;
import es.caib.zkib.zkiblaf.Missatgebox;

public class Am02Handler extends Window implements AfterCompose {
	private static final String AWS = "AWS";
	private static final String GOOGLE = "Google";
	private static final String AZURE = "Azure";
	private static final String OPENID = "Openid";
	private static final String SAML = "SAML";
	private Wizard wizard;
	private CustomField3 name;
	private CustomField3 port;
	private System currentSystem;
	private Html explanation;
	FederationService svc;
	private String publicId;
	private Textbox copytb;
	private String type;
	private String serviceProvider;
	private CustomField3 googleDomain;
	private Div step3saml;
	private Div step3openid;
	private CustomField3 oid_implicit;
	private CustomField3 openidUrl;
	private CustomField3 oid_password;
	private CustomField3 oid_passsword_clientcred;
	private CustomField3 oid_authcode;
	private CustomField3 openidName;
	private CustomField3 openidSecret;
	private CustomField3 openidClientId;
	
	@Override
	public void afterCompose() {
		wizard = (Wizard) getFellow("wizard");
		name = (CustomField3) getFellow("name");
		port = (CustomField3) getFellow("port");
		explanation = (Html) getFellow("explanation");
		copytb = (Textbox) getFellow("copytb");
		googleDomain = (CustomField3) getFellow("googledomain");
		step3saml = (Div) getFellow("step3saml");
		step3openid = (Div) getFellow("step3openid");
		oid_implicit = (CustomField3) getFellow("oid_implicit");
		oid_authcode = (CustomField3) getFellow("oid_authcode");
		oid_passsword_clientcred = (CustomField3) getFellow("oid_passsword_clientcred");
		oid_password = (CustomField3) getFellow("oid_password");
		openidUrl = (CustomField3) getFellow("openidUrl");
		openidName = (CustomField3) getFellow("openidName");
		openidClientId = (CustomField3) getFellow("openidClientId");
		openidSecret = (CustomField3) getFellow("openidSecret");
		
		doHighlighted();
		boolean sp = false, idp = false;
		try {
			svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			for (FederationMember member: svc.findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "I")) {
				if (member.getClasse().equals("I") &&  member.getIdpType() == IdentityProviderType.SOFFID) {
					publicId = member.getPublicId();
					idp = true;
				}
				if (member.getClasse().equals("S"))
					sp = true;
			}
			if (idp)
				wizard.next();
		} catch (Exception e) {
			throw new UiException(e);
		}

	}
	
	public void back(Event ev) {
		if (wizard.getSelected() <= 1)
			detach();
		else {
			googleDomain.setVisible(type == GOOGLE);
			wizard.previous();
		}
	}
	
	public void next(Event ev) throws Exception {
		switch (wizard.getSelected()) {
		case 0:
			if (validateConnectionAttributes()) {
				System s2 = EJBLocator.getDispatcherService().findDispatcherByName("IdP");
				if (s2 == null) {
					createIdp();
					createAgent();
				} else {
					String msg = String.format(Labels.getLabel("wizard-ad.confirmReplace"), s2.getName());
					Missatgebox.confirmaOK_CANCEL(msg, (ev2) -> {
						if (ev2.getName().equals("onOK")) {
							Window w = (Window) ev.getTarget().getSpaceOwner();
							w.detach();
							createIdp();
							createAgent();
						}				
					});
				}
			}
			break;
		case 2: // UploadMetadata
 			generateMetadata();
 			break;
		case 4:
			Executions.getCurrent().sendRedirect("/addon/federation/providers.zul?filter="+serviceProvider, "_blank");
			
			detach();
		default:
			wizard.next();
			break;
		}
	}

	private void generateMetadata() throws InternalErrorException, TransformerConfigurationException, FactoryConfigurationError, SAXException, ParserConfigurationException, TransformerFactoryConfigurationError, TransformerException, NoSuchAlgorithmException {
		getFellow("azuredownloaddiv").setVisible(false);
		getFellow("step4saml").setVisible(false);
		getFellow("step4openid").setVisible(false);
		createPublicPolicy();
		if (type == GOOGLE) {
			if (googleDomain.attributeValidateAll()) {
				String domain = googleDomain.getValue().toString();
				serviceProvider = "google.cam/a/"+domain;
				String metadata = "<EntityDescriptor entityID=\"google.com/a/"+domain+"\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n"
						+ "			<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n"
						+ "			<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>\n"
						+ "			<AssertionConsumerService index=\"1\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n"
						+ "			Location=\"https://www.google.com/a/soffid.com/acs\" >\n"
						+ "			</AssertionConsumerService>\n"
						+ "			</SPSSODescriptor>\n"
						+ "			</EntityDescriptor>\n";
				createServiceProvider(metadata);
				wizard.next();
				wizard.next();
			}
		}
		else if (type == AZURE) {
			try {
				final URL url = new URL("https://nexus.microsoftonline-p.com/federationmetadata/saml20/federationmetadata.xml");
				HttpURLConnection conn = (HttpURLConnection) url.openConnection();
				InputStream in = conn.getInputStream();
				if (registerServiceProvider(in)) {
					wizard.next();
					wizard.next();
				}
			} catch (IOException e) {
				getFellow("step4saml").setVisible(true);
				getFellow("azuredownloaddiv").setVisible(true);
				wizard.next();
			}
			
		}
		else if (type == OPENID) {
			openidUrl.setWarning(0, "");
			if (!openidName.attributeValidateAll())
				return;
			boolean b1 = Boolean.TRUE.equals(oid_authcode.getValue());
			boolean b2 = Boolean.TRUE.equals(oid_implicit.getValue());
			boolean b3 = Boolean.TRUE.equals(oid_password.getValue());
			boolean b4 = Boolean.TRUE.equals(oid_passsword_clientcred.getValue());
			if (! b1 && ! b2 && ! b3 && ! b4 ) {
				openidUrl.setWarning(0, Labels.getLabel("federation.sso.selectFlow"));
				return;
			}
			List<String> r = (List<String>) openidUrl.getValue();
			if ((b1 || b2) && (r == null || r.isEmpty())) {
				openidUrl.setWarning(0, "Please, enter a value" );
				return;
			}
			createOpenidServiceProvider();
			getFellow("step4openid").setVisible(true);
			wizard.next();
		}
		else
		{
			getFellow("step4saml").setVisible(true);
			wizard.next();
		}
	}

	private void createOpenidServiceProvider() throws InternalErrorException, NoSuchAlgorithmException {
		serviceProvider = openidName.getValue().toString();
		EntityGroup eg = createEntityGroup(svc, "Service providers");
		FederationMember fm = svc.findFederationMemberByPublicId(serviceProvider);
		if (fm == null)
			fm = new FederationMember();
		fm.setPublicId(serviceProvider);
		fm.setClasse("S");
		fm.setName(serviceProvider);
		fm.setEntityGroup(eg);
		fm.setServiceProviderType(ServiceProviderType.OPENID_CONNECT);

		HashSet<String> s = new HashSet<>();
		final boolean im = Boolean.TRUE.equals(oid_implicit.getValue());
		final boolean ac = Boolean.TRUE.equals(oid_authcode.getValue());
		final boolean pa = Boolean.TRUE.equals(oid_password.getValue());
		final boolean pc = Boolean.TRUE.equals(oid_passsword_clientcred.getValue());
		if ( im) s.add("IM");
		if ( ac) s.add("AC");
		if ( pa) s.add("PA");
		if ( pc) s.add("PC");
		fm.setOpenidMechanism(s);
		fm.setOpenidUrl((List<String>) openidUrl.getValue());
		fm.setOpenidClientId(generateSecret());
		if (ac || pc) {
			final String secret = generateSecret();
			fm.setOpenidSecret(new Digest(secret));
			openidSecret.setValue(secret);
		} else {
			fm.setOpenidSecret(null);
			openidSecret.setValue("");
		}

		openidClientId.setValue(fm.getOpenidClientId());
		
		if (fm.getId() == null)
			fm = svc.create(fm);
		else
			svc.update(fm);
		
	}

	private String generateSecret() {
		byte b[] = new byte[36];
		new SecureRandom().nextBytes(b);
		return Base64.encodeBytes(b, Base64.DONT_BREAK_LINES);
	}

	private void createServiceProvider(String metadata) throws InternalErrorException {
		EntityGroup eg = createEntityGroup(svc, "Cloud providers");
		FederationMember fm = svc.findFederationMemberByPublicId(serviceProvider);
		if (fm == null)
			fm = new FederationMember();
		fm.setPublicId(serviceProvider);
		fm.setClasse("S");
		fm.setName(type+" "+serviceProvider);
		fm.setMetadades(metadata);
		fm.setEntityGroup(eg);
		fm.setServiceProviderType(ServiceProviderType.SAML);
		if (fm.getId() == null)
			fm = svc.create(fm);
		else
			svc.update(fm);
	}

	private void createAgent() throws Exception {
		// --------------- Create the agent
		System s = new System();
		s.setName("IdP");
		s.setDescription("Soffid Identity Provider");
		s.setAccessControl(false);
		s.setAuthoritative(false);
		s.setClassName("es.caib.seycon.idp.agent.IDPAgent");
		s.setManualAccountCreation(false);
		s.setParam0(publicId);
		s.setPasswordsDomain("DEFAULT");
		s.setReadOnly(false);
		s.setRolebased(false);
		s.setSharedDispatcher(false);
		s.setTrusted(false);
		s.setUrl("local");
		s.setUsersDomain("DEFAULT");
		s.setUserTypes("I,E");
		
		System s2 = EJBLocator.getDispatcherService().findDispatcherByName(s.getName());
		if (s2 == null) {
			s = EJBLocator.getDispatcherService().create(s);
			checkConnectivity(s, s);
			wizard.next();
		} else {
			final System ss = s;
			ss.setId(s2.getId());
			System s3 = EJBLocator.getDispatcherService().update(ss);
			checkConnectivity(s3, null);
			wizard.next();
		}
	}

	private void checkConnectivity(System s, System s2) throws InternalErrorException, NamingException, CreateException, Exception {
		// --------------------- Check connectivity
		currentSystem = s;
		final DispatcherService dispatcherService = EJBLocator.getDispatcherService();
		try {
			dispatcherService.checkConnectivity(s.getName());
			dispatcherService.applyConfigurationAsync(s);
			Thread.sleep(2000);
		} catch (Exception e) {
			FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			if (s2 != null) {
				dispatcherService.delete(s);
			}
			final String publicId = "https://"+name.getValue().toString();
			FederationMember fm = svc.findFederationMemberByPublicId(publicId);
			if (fm != null)  {
				svc.delete(fm);
			}
 			throw e;
		}
	}

	
	private void createIdp() throws NamingException, InternalErrorException {
		FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
		EntityGroup eg = createEntityGroup(svc, "Soffid");
		
		publicId = "https://"+name.getValue().toString().trim();
		FederationMember fm = svc.findFederationMemberByPublicId(publicId);
		if (fm != null) 
			return;
		
		
		FederationMember m = new FederationMember();

		m.setPublicId(publicId);
		m.setAllowRecover(false);
		m.setAllowRegister(false);
		m.setAlwaysAskForCredentials(false);
		m.setAuthenticationMethods("P");
		m.setClasse("I");
		m.setConsent(false);
		m.setContact("issues@soffid.com");
		m.setDisableSSL(false);
		m.setEntityGroup(eg);
		m.setHostName(name.getValue().toString().trim());
		m.setIdpType(IdentityProviderType.SOFFID);
		m.setName("Soffid identity provider");
		m.setRegisterExternalIdentities(false);
		m.setSessionTimeout(120L * 60L);
		m.setSsoCookieName("_idp_session");
		m.setStandardPort(port.getValue().toString());
		m = svc.create(m);
		
		// Create SAML Profile
		SAMLProfile p = new SAMLProfile();
		p.setClasse(SamlProfileEnumeration.SAML2_SSO);
		p.setEnabled(true);
		p.setSignAssertions(SAMLRequirementEnumeration.CONDITIONAL);
		p.setSignRequests(SAMLRequirementEnumeration.ALWAYS);
		p.setSignResponses(SAMLRequirementEnumeration.ALWAYS);
		p.setEncryptAssertions(SAMLRequirementEnumeration.NEVER);
		p.setEncryptNameIds(SAMLRequirementEnumeration.NEVER);
		p.setIdentityProvider(m);
		p.setIncludeAttributeStatement(true);
		svc.create(p);
		
		// Create Openid Profile
		p = new SAMLProfile();
		p.setClasse(SamlProfileEnumeration.OPENID);
		p.setEnabled(true);
		p.setAuthorizationEndpoint("/authorize");
		p.setRevokeEndpoint("/revoke");
		p.setTokenEndpoint("/token");
		p.setUserInfoEndpoint("/userinfo");
		p.setIdentityProvider(m);
		svc.create(p);
	}

	private EntityGroup createEntityGroup(FederationService svc, String name) throws InternalErrorException {
		EntityGroup eg = null;
		Collection<EntityGroupMember> l = svc.findEntityGroupByNom(name);
		
		if ( ! l.isEmpty()) eg = l.iterator().next().getEntityGroup();
		
		if (eg == null) {
			eg = new EntityGroup(name);
			eg = svc.create(eg);
		}
		return eg;
	}

	private boolean validateConnectionAttributes() {
		if (name.attributeValidateAll()) {
			String host = name.getValue().toString();
			try {
				InetAddress.getByName(host);
			} catch (Exception e) {
				name.setWarning(0, Labels.getLabel("wizard-servicenow.wrongHost"));
				return false;
			}
			if (port.getValue() == null || port.getValue().toString().trim().isEmpty()) {
				port.setValue("443");
			}
			try {
				long l = Long.parseLong(port.getValue().toString());
				if (l < 1 || l > 65535)
					port.setWarning(0, Labels.getLabel("federation.registeridp.portNumberRestriction"));
			} catch (NumberFormatException e) {
				port.setWarning(0, Labels.getLabel("federation.registeridp.portNumberRestriction"));
				return false;
			}
			return true;
		} else {
			return false;
		}
	}

	public void addAws(Event e) throws InternalErrorException {
		type = AWS;
		wizard.next();
		step3openid.setVisible(false);
		step3saml.setVisible(true);
		String s = Labels.getLabel("federation.sso.aws1");
		
		FederationMember fm = svc.findFederationMemberByPublicId(publicId);
		s = s.replace("{signinurl}", 
				 "<span>"
				+ encode("https://"+fm.getHostName()+":"+fm.getStandardPort()+"/profile/SAML2/Redirect/SSO")
				+"</span>"
				+ copyButton2())
			.replace("{issuer}", 
				 "<span>"
				+ encode(publicId)
				+"</span>"
				+ copyButton2());
		explanation.setContent(s);
		
		AMedia m = new AMedia(fm.getHostName()+"-cert.pem", null, "binary/octect-stream", 
				fm.getCertificateChain().getBytes(StandardCharsets.UTF_8));
		Filedownload.save(m);
	}

	public void addOasis(Event e) throws InternalErrorException {
		type = SAML;
		wizard.next();
		step3openid.setVisible(false);
		step3saml.setVisible(true);
		String s = Labels.getLabel("federation.sso.saml1");
		
		FederationMember fm = svc.findFederationMemberByPublicId(publicId);
		s = s.replace("{url}", 
				encode("https://"+fm.getHostName()+":"+fm.getStandardPort()+"/SAML/metadata.xml"));
		explanation.setContent(s);
		
		AMedia m = new AMedia(fm.getHostName()+"-metadata.xml", null, "binary/octect-stream", 
				fm.getMetadades().getBytes(StandardCharsets.UTF_8));
		Filedownload.save(m);
	}

	public void addGoogle(Event e) throws InternalErrorException {
		type = GOOGLE;
		wizard.next();
		step3openid.setVisible(false);
		step3saml.setVisible(true);
		String s = Labels.getLabel("federation.sso.google1");
		
		FederationMember fm = svc.findFederationMemberByPublicId(publicId);
		s = s.replace("{signinurl}", 
				 "<span>"
				+ encode("https://"+fm.getHostName()+":"+fm.getStandardPort()+"/profile/SAML2/Redirect/SSO")
				+"</span>"
				+ copyButton2())
			.replace("{logouturl}", 
				 "<span>"
				+ encode("https://"+fm.getHostName()+":"+fm.getStandardPort()+"/logout.jsp")
				+"</span>"
				+ copyButton2())
			.replace("{passwordurl}", 
				 "<span>"
				+ encode("https://"+fm.getHostName()+":"+fm.getStandardPort()+"/protected/passwordChange")
				+"</span>"
				+ copyButton2());
		explanation.setContent(s);
		
		AMedia m = new AMedia(fm.getHostName()+"-cert.pem", null, "binary/octect-stream", 
				fm.getCertificateChain().getBytes(StandardCharsets.UTF_8));
		Filedownload.save(m);
		
		googleDomain.setVisible(true);
	}


	public void addAzure(Event e) throws InternalErrorException {
		type = AZURE;
		wizard.next();
		step3openid.setVisible(false);
		step3saml.setVisible(true);
		
		FederationMember fm = svc.findFederationMemberByPublicId(publicId);
		String cert = fm.getCertificateChain();
		int i = cert.indexOf("-----END");
		if (i >= 0) cert = cert.substring(0,i);
		cert = cert.replace("-----BEGIN CERTIFICATE-----", "")
				.replace("\r","")
				.replace("\n", "")
				.replace(" ", "");
		
		String cmd = "Set-MsolDomainAuthentication `\n"
				+ "  -FederationBrandName \"Soffid IdP\" `\n"
				+ "  -Authentication Federated `\n"
				+ "  -PassiveLogOnUri \"https://"+fm.getHostName()+":"+fm.getStandardPort()+"/profile/SAML2/Redirect/SSO\" `\n"
				+ "  -SigningCertificate $MySigningCert \""+cert+"\" `\n"
				+ "  -IssuerUri \""+publicId+"\" `\n"
				+ "  -LogOffUri \"https://"+fm.getHostName()+":"+fm.getStandardPort()+"/logout.jsp\" `\n"
				+ "  -PreferredAuthenticationProtocol \"SAMLP\" \n";
		
		String s = Labels.getLabel("federation.sso.azure1");
		s = s.replace("{cmd}", 
				 "<span style='max-height: 150px; display: inline-block; overflow: scroll; width: 100%;font-family: monospace; width: calc(100% - 40px)'>"
				 + encode(cmd)
				+"</span>"
				+ copyButton2("top"))
				.replace("{cmd2}", "<span>Install-Module MSOnline</span>"+copyButton2()) 
				.replace("{cmd3}", "<span>Connect-Msolservice</span>"+copyButton2());
		explanation.setContent(s);
		
		AMedia m = new AMedia(fm.getHostName()+"-cert.pem", null, "binary/octect-stream", 
				fm.getCertificateChain().getBytes(StandardCharsets.UTF_8));
	}

	public void addOpenid(Event e) throws InternalErrorException {
		type = OPENID;
		wizard.next();
		step3openid.setVisible(true);
		step3saml.setVisible(false);
		
		FederationMember fm = svc.findFederationMemberByPublicId(publicId);
		
		
	}

	private String copyButton2() {
		return copyButton2("middle");
	}
	
	private String copyButton2(String va) {
		return "<img class='imageclic' src='"+Executions.getCurrent().getContextPath()+"/img/copy.svg' "
				+ "style='vertical-align: "+va+"; height: 24px; width: 24px; padding: 1px' "
				+ "onclick=\"{var e = document.getElementById('"+copytb.getUuid()+"'); "
				+ "e.value=this.previousElementSibling.innerText;"
				+ "e.style.display='inline';"
				+ "e.focus(); "
				+ "e.select();"
				+ "document.execCommand('copy');"
				+ "e.style.display='none';}\">";
	}

	private String encode(String string) {
		return string.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>");
	}
	
	public void uploadMetadata(UploadEvent ev) {
		for (Media file: ev.getMedias()) {
			try {
				final InputStream inputStream = file.getStreamData();
				if (registerServiceProvider(inputStream))
					wizard.next();
			} catch (SAXException e) {
				Missatgebox.avis(Labels.getLabel("federation.sso.samlParseError"));
			} catch (Exception e) {
				throw new UiException(e);
			}
		}
	}

	private boolean registerServiceProvider(final InputStream inputStream) throws FactoryConfigurationError, SAXException,
			IOException, ParserConfigurationException, InternalErrorException, TransformerFactoryConfigurationError,
			TransformerConfigurationException, TransformerException {
		DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
		f.setNamespaceAware(true);
		Document doc = f.newDocumentBuilder().parse(inputStream);
		Element element = doc.getDocumentElement();
		if (element == null || !"EntityDescriptor".equals(element.getLocalName())) {
			Missatgebox.avis(Labels.getLabel("federation.sso.samlParseError"));
			return false;
		}
		String publicId = element.getAttribute("entityID");
		if (publicId == null) {
			Missatgebox.avis(Labels.getLabel("federation.sso.samlParseError2"));
			return false;
		}
		
		EntityGroup eg = createEntityGroup(svc, "Cloud providers");
		FederationMember fm = svc.findFederationMemberByPublicId(publicId);
		if (fm == null)
			fm = new FederationMember();
		fm.setPublicId(publicId);
		fm.setClasse("S");
		fm.setName(type);
		
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		fm.setMetadades(writer.getBuffer().toString());
		fm.setEntityGroup(eg);
		fm.setServiceProviderType(ServiceProviderType.SAML);
		
		if (fm.getId() == null)
			fm = svc.create(fm);
		else
			svc.update(fm);
		
		serviceProvider = fm.getPublicId();
		
		if (type == AZURE)
			createAzurePolicy();

		return true;
	}
	
	void createPublicPolicy () throws InternalErrorException {
		for (Policy policy: svc.findPolicies()) {
			if (policy.getName().equals("Public"))
				return;
		}
		
		Policy p = new Policy();
		p.setName("Public");
		PolicyCondition c = new PolicyCondition();
		c.setType(ConditionType.ANY);
		p.setCondition(c);
		p = svc.create(p);
		
		for (String attName: new String[] {"uid", "mail"}) {
			for (Attribute att: svc.findAtributs(null, attName, null)) {
				AttributePolicy ap = new AttributePolicy();
				ap.setAttribute(att);
				ap.setAttributePolicyCondition(new AttributePolicyCondition());
				ap.getAttributePolicyCondition().setType(ConditionType.ANY);
				ap.getAttributePolicyCondition().setAttribute(att);
				ap.setPolicyId(p.getId());
				p.getAttributePolicy().add(ap);
			}
		}
		
		svc.update(p);
	}

	void createAzurePolicy () throws InternalErrorException {
		for (Policy policy: svc.findPolicies()) {
			if (policy.getName().equals("Azure"))
				return;
		}
		
		Attribute att;
		Collection<Attribute> list = svc.findAtributs(null, "IDPEmail", null);
		if (list.isEmpty()) {
			att = new Attribute();
			att.setName("Email for Azure");
			att.setOid("IDPEmail");
			att.setOpenidName(null);
			att.setShortName("IDPEmail");
			att.setValue("shortName+\"@\"+mailDomain");
			att = svc.create(att);
		} else {
			att = list.iterator().next();
		}
		
		Policy p = new Policy();
		p.setName("Azure");
		PolicyCondition c = new PolicyCondition();
		c.setType(ConditionType.ATTRIBUTE_REQUESTER_STRING);
		c.setValue(serviceProvider);
		p.setCondition(c);
		
		p = svc.create(p);

		AttributePolicy ap = new AttributePolicy();
		ap.setAttribute(att);
		ap.setAttributePolicyCondition(new AttributePolicyCondition());
		ap.getAttributePolicyCondition().setType(ConditionType.ANY);
		ap.getAttributePolicyCondition().setAttribute(att);
		ap.setPolicyId(p.getId());
		p.getAttributePolicy().add(ap);
		
		svc.create(p);
	}
}
