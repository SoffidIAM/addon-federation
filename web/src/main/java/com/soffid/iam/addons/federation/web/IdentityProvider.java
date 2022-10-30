package com.soffid.iam.addons.federation.web;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.xml.parsers.ParserConfigurationException;

import org.json.JSONException;
import org.json.JSONObject;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import org.zkoss.util.media.Media;
import org.zkoss.zhtml.impl.AbstractTag;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.UploadEvent;
import org.zkoss.zk.ui.ext.AfterCompose;
import org.zkoss.zul.Button;
import org.zkoss.zul.Filedownload;
import org.zkoss.zul.Window;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.api.Password;
import com.soffid.iam.bpm.api.ProcessDefinition;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.component.InputField3;
import com.soffid.iam.web.component.ObjectAttributesDiv;
import com.soffid.iam.web.popup.FileUpload2;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.binder.BindContext;
import es.caib.zkib.component.DataTable;
import es.caib.zkib.component.Form2;
import es.caib.zkib.component.Wizard;
import es.caib.zkib.datamodel.DataNode;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.events.XPathEvent;
import es.caib.zkib.events.XPathRerunEvent;
import es.caib.zkib.events.XPathSubscriber;
import es.caib.zkib.zkiblaf.Missatgebox;

public class IdentityProvider extends Form2 implements XPathSubscriber, AfterCompose {

	private String certPath;
	private String publicKeyPath;
	private String keyPath;
	private byte[] data;

	ProviderHandler getFrame() {
		return (ProviderHandler) getPage().getFellow("frame");
	}
	
	public void onChangeType (Event event) {
		enableIDPComponents();
		IdentityProviderType idpType = (IdentityProviderType) ((CustomField3) event.getTarget()).getValue();
		if (idpType.equals (IdentityProviderType.GOOGLE))
		{
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/publicId", "http://google.com");
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/name", "Google");
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/metadades", 
				"{\"discoveryUrl\":\"https://accounts.google.com/.well-known/openid-configuration\"}");
		}
		if (idpType.equals (IdentityProviderType.FACEBOOK))
		{
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/publicId", "http://facebook.com");
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/name", "Facebook");
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/metadades", 
				"");
		}
		if (idpType.equals (IdentityProviderType.LINKEDIN))
		{
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/publicId", "http://linkedin.com");
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/name", "Linkedin");
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/metadades", 
				"");
		}
		if (idpType.equals (IdentityProviderType.OPENID_CONNECT))
		{
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/publicId", "");
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/name", "");
			es.caib.zkib.datasource.XPathUtils.setValue(this, "/federationMember/metadades", 
				"{\n \"authorization_endpoint\": \"https://server/oauth2/auth\",\n"+
				" \"token_endpoint\": \"https://server/oauth2/token\",\n"+
					" \"userinfo_endpoint\": \"https://server/oauth2/userinfo\",\n"+
				" \"scopes_supported\": [ \"openid\",\"email\",\"profile\"]\n}");
		}
		
		{
			es.caib.zkib.binder.BindContext bctx = es.caib.zkib.datasource.XPathUtils.getComponentContext(this);
			bctx.getDataSource().sendEvent(new es.caib.zkib.events.XPathRerunEvent(bctx.getDataSource(),bctx.getXPath()) );
		}
		enableIDPComponents();

	}
	
	public void enableIDPComponents ()
	{
		String clazz = (String) XPathUtils.eval(this, "federationMember/classe");
		IdentityProviderType idpType = (IdentityProviderType) es.caib.zkib.datasource.XPathUtils.eval(this, "/federationMember/idpType");
		boolean marcat = IdentityProviderType.SOFFID.equals(idpType);
		getFellow("idpType").setVisible("I".equals(clazz));
		getFellow("networkSection").setVisible(marcat && !clazz.equals("V"));
		getFellow("certificateSection").setVisible(marcat || clazz.equals("V") || idpType == IdentityProviderType.SAML);
		getFellow("provisionSection").setVisible(!marcat  && !clazz.equals("V"));
		getFellow("advancedSection").setVisible(marcat || clazz.equals("V"));
		getFellow("authenticationSection").setVisible(marcat || clazz.equals("V"));
		getFellow("kerberosDiv").setVisible(marcat && !clazz.equals("V"));
		getFellow("sessionSection").setVisible(marcat && !clazz.equals("V"));
		getFellow("serviceProvidersSection").setVisible(clazz.equals("V"));
		getFellow("uiSection").setVisible(marcat);
		
		if ( IdentityProviderType.FACEBOOK.equals( idpType ) )
		{
			getFellow("fed_ext_link").setVisible(true);
			((AbstractTag)getFellow("fed_ext_link")).setDynamicProperty("href", "http://developers.facebook.com");
		}
		else if ( IdentityProviderType.GOOGLE.equals( idpType ) )
		{
			getFellow("fed_ext_link").setVisible(true);
			((AbstractTag)getFellow("fed_ext_link")).setDynamicProperty("href", "https://console.developers.google.com/apis/dashboard");
		}
		else if ( IdentityProviderType.LINKEDIN.equals( idpType ) )
		{
			getFellow("fed_ext_link").setVisible(true);
			((AbstractTag)getFellow("fed_ext_link")).setDynamicProperty("href", "https://www.linkedin.com/developer/apps/new");
		}
		else
		{
			getFellow("fed_ext_link").setVisible(false);
		}
		
		
		getFellow("metadades").setVisible(IdentityProviderType.SOFFID.equals( idpType ) ||
				IdentityProviderType.SAML.equals( idpType ) ||
				IdentityProviderType.OPENID_CONNECT.equals( idpType ));
		((CustomField3)getFellow("metadades")).setDisabled(IdentityProviderType.SOFFID.equals( idpType ));
		getFellow("oauthKey").setVisible(IdentityProviderType.FACEBOOK.equals( idpType ) ||
				IdentityProviderType.GOOGLE.equals( idpType ) ||
				IdentityProviderType.LINKEDIN.equals( idpType ) ||
				IdentityProviderType.OPENID_CONNECT.equals( idpType ));
		getFellow("oauthSecret").setVisible(IdentityProviderType.FACEBOOK.equals( idpType ) ||
				IdentityProviderType.GOOGLE.equals( idpType ) ||
				IdentityProviderType.LINKEDIN.equals( idpType ) ||
				IdentityProviderType.OPENID_CONNECT.equals( idpType ));

		Boolean allowRegister = (Boolean) XPathUtils.eval(this, "federationMember/allowRegister");
		if ( Boolean.TRUE.equals(allowRegister) && marcat)
		{
			((CustomField3)getFellow("userTypeToRegister")).setVisible(true);
			((CustomField3)getFellow("groupToRegister")).setVisible(true);
			((CustomField3)getFellow("groupToRegister")).setDisabled(false);
			((CustomField3)getFellow("groupToRegister")).setRequired(true);
			((CustomField3)getFellow("userTypeToRegister")).setDisabled(false);
		} else {
			((CustomField3)getFellow("userTypeToRegister")).setVisible(false);
			((CustomField3)getFellow("groupToRegister")).setVisible(false);
			((CustomField3)getFellow("groupToRegister")).setDisabled(true);
			((CustomField3)getFellow("groupToRegister")).setRequired(false);
			((CustomField3)getFellow("userTypeToRegister")).setDisabled(true);
		}
//		boolean showCert = marcat && ! Boolean.TRUE.equals(XPathUtils.eval(this, "federationMember/disableSSL"));
//		getFellow("port2").setVisible(showCert);
		getFellow("sslKey").setVisible(true);
		getFellow("certificatechainSsl").setVisible(true);
		getFellow("profilesSection").setVisible(
				IdentityProviderType.SOFFID.equals( idpType ) || "V".equals(clazz));
		serviceProviderSelect(null);
	}	

	public void onChangePublicId(Event event) {
		onChangeName(event);
	}
	
	public void onChangeName(Event event) {
		try {
			final Object publicId = XPathUtils.eval(this, "federationMember/publicId");
			Object name = XPathUtils.eval(this, "federationMember/name");
			if (name == null) name = "";
			XPathUtils.setValue(this, "description", publicId + " - " + name);
		} catch (Exception e) {
		}
	}
	
	public void changeMetadata(Event event) throws ParserConfigurationException, SAXException, IOException {
        try {
        	CustomField3 md = (CustomField3) event.getTarget();
        	CustomField3 publicid = (CustomField3) getFellow("idpPublicId");;
        	
        	IdentityProviderType idpType = (IdentityProviderType) es.caib.zkib.datasource.XPathUtils.eval(this, "/federationMember/idpType");
        	if (idpType.equals( IdentityProviderType.SAML) ||
        			idpType.equals( IdentityProviderType.SOFFID))
        	{
                javax.xml.parsers.DocumentBuilderFactory dbFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
                dbFactory.setNamespaceAware(true);
                javax.xml.parsers.DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
                org.w3c.dom.Document newDoc = dBuilder.parse(new org.xml.sax.InputSource(new java.io.StringReader((String) md.getValue())));
                org.w3c.dom.NodeList nl = newDoc.getChildNodes();
                for (int i = 0; i < nl.getLength(); i++) {
                    org.w3c.dom.Node n = nl.item(i);
                    if (n instanceof Element)
                    {
                    	String id = ((Element) n).getAttribute("entityID");
                    	if (id != null)
                    	{
                    		publicid.setValue( id );
                    		onChangeName(event);
                    	}
                    }
                }
        	} else if (idpType.equals( IdentityProviderType.OPENID_CONNECT) ) {
        		JSONObject json = new org.json.JSONObject( (String) md.getValue() );
        	}
        } catch (org.xml.sax.SAXParseException e) {
        	es.caib.zkib.zkiblaf.Missatgebox.avis("Error parsing metadata: "+e.getMessage());
        } catch (JSONException e) {
        	es.caib.zkib.zkiblaf.Missatgebox.avis("Error parsing metadata: "+e.getMessage());
        }

	}

	@Override
	public void onUpdate(XPathEvent event) {
		try {
			String type = (String) XPathUtils.eval(this, "type");
			if ( "IDP".equals(type) || "VIP".equals(type)) {
				enableIDPComponents();
			}
			if (event instanceof XPathRerunEvent) {
				DataTable dt = (DataTable) getFellow("keytabsgrid");
				dt.setDataPath(dt.getDataPath());
				getFellow("deleteKeytabButton").setVisible(false);
			}
		} catch (Exception e) {}
	}
	
	public void generateKey(Event ev) throws InternalErrorException, NamingException {
		generateKeys("/federationMember/privateKey", "/federationMember/publicKey", "/federationMember/certificateChain", "/federationMember/publicId");
	}

	public void generateSslKey(Event ev) throws InternalErrorException, NamingException {
		generateKeys("/federationMember/sslPrivateKey", "/federationMember/sslPublicKey", "/federationMember/sslCertificate", "/federationMember/hostName");
	}

	public void generateKeys(String keyPath, String publicKeyPath, String certPath, String namePath) throws InternalErrorException, NamingException {
		String key = (String) XPathUtils.eval(this, keyPath) ;
		if (key != null) {
			Missatgebox.confirmaYES_NO(
					org.zkoss.util.resource.Labels.getLabel("federacio.SegurCanvi"),
					org.zkoss.util.resource.Labels.getLabel("federacio.Confirmacio"),
					(event) -> {
						if (event.getName().equals("onYes"))
							doGenerateKeys (keyPath, publicKeyPath, certPath, namePath);
					}
			);
		} else
		{
			doGenerateKeys (keyPath, publicKeyPath, certPath, namePath);
		}
	}
	
	private void doGenerateKeys(String keyPath, String publicKeyPath, String certPath, String namePath) throws InternalErrorException, NamingException {
		FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);

		String[] res = svc.generateKeys(  (String) XPathUtils.eval(this, namePath) );
	
		XPathUtils.setValue(this, publicKeyPath, res[0]);
		XPathUtils.setValue(this, keyPath, res[1]);
		XPathUtils.setValue(this, certPath, res[2]);
		Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.GeneradoOK"));	
	}

	public void deleteKey(Event ev) throws InternalErrorException, NamingException {
		deleteKeys("/federationMember/privateKey", "/federationMember/publicKey", "/federationMember/certificateChain", "/federationMember/publicId");
	}

	public void deleteSslKey(Event ev) throws InternalErrorException, NamingException {
		deleteKeys("/federationMember/sslPrivateKey", "/federationMember/sslPublicKey", "/federationMember/sslCertificate", "/federationMember/hostName");
	}

	private void deleteKeys(String keyPath, String publicKeyPath, String certPath, String namePath) throws InternalErrorException, NamingException {
		XPathUtils.setValue(this, publicKeyPath, null);
		XPathUtils.setValue(this, keyPath, null);
		XPathUtils.setValue(this, certPath, null);
		Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.BorratOK"));	
	}
	
	public void generatePKCS10(Event ev) throws InternalErrorException, NamingException {
		generatePkcs10("/federationMember/privateKey", "/federationMember/publicKey", "/federationMember/certificateChain", "/federationMember/publicId");
	}

	public void generateSslPKCS10(Event ev) throws InternalErrorException, NamingException {
		generatePkcs10("/federationMember/sslPrivateKey", "/federationMember/sslPublicKey", "/federationMember/sslCertificate", "/federationMember/hostName");
	}

	private void generatePkcs10(String keyPath, String publicKeyPath, String certPath, String namePath) throws InternalErrorException, NamingException {
		FederationMember fm = (FederationMember) XPathUtils.eval(this, "/federationMember");

		String priv = (String) XPathUtils.eval(this, keyPath);
		String pub = (String) XPathUtils.eval(this, publicKeyPath);
		
		if (priv !=null && ! priv.trim().isEmpty()) {
			FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			String res = svc.generatePKCS10(fm, priv, pub);

			String nom = fm.getName();
			
			if (nom==null || nom.trim().isEmpty()) nom = "pkcs10"; 
			else nom = nom+".pkcs10"; 
			
			org.zkoss.util.media.AMedia pkcs = new org.zkoss.util.media.AMedia(nom,"txt","binary/octet-stream",res);
			Filedownload.save(pkcs);
		}
	}

	public void uploadPkcs12(Event ev) throws InternalErrorException, NamingException {
		uploadPkcs12("/federationMember/privateKey", "/federationMember/publicKey", "/federationMember/certificateChain", "/federationMember/publicId");
	}

	public void uploadSslPkcs12(Event ev) throws InternalErrorException, NamingException {
		uploadPkcs12("/federationMember/sslPrivateKey", "/federationMember/sslPublicKey", "/federationMember/sslCertificate", "/federationMember/hostName");
	}

	private void uploadPkcs12(String keyPath, String publicKeyPath, String certPath, String namePath) throws InternalErrorException, NamingException {
		this.keyPath = keyPath;
		this.publicKeyPath = publicKeyPath;
		this.certPath = certPath;
		data = null;
		Window w = (Window) getFellow("pkcs12");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		wizard.setSelected(0);
		w.doHighlighted();
	}
	
	public void cancelUpload(Event event) throws IOException {
		if (data == null) {
			Window w = (Window) getFellow("pkcs12");
			w.setVisible(false);
		}
	}
	
	public void onUpload(UploadEvent event) throws IOException {
		Media m = event.getMedia();

		Window w = (Window) getFellow("pkcs12");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		if (m.isBinary())
		{
			if (m.inMemory())
				data = m.getByteData();
			else
			{
				java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
				java.io.InputStream in = m.getStreamData();
				byte [] b = new byte[4096];
				int read = in.read(b);
				while (read > 0)
				{
					out.write (b, 0, read);
					read = in.read(b);
				}
				in.close ();
				out.close();
				data = out.toByteArray();
			}
		} else {
			StringBuffer b = new StringBuffer();
			if (m.inMemory())
				b .append(m.getStringData());
			else
			{
				java.io.Reader r = m.getReaderData();
				int read = r.read();
				while (read >= 0)
				{
					b.append ((char) read);
					read = r.read();
				}
			}
			data = b.toString().getBytes("UTF-8");
		}
		wizard.next();
	}
	
	public void step2back(Event event) {
		Window w = (Window) getFellow("pkcs12");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		((CustomField3) event.getTarget().getFellow("pin")).setValue(null);
		wizard.previous();
	}
	
	public void doUploadPcks12(Event event) throws NamingException {
		FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);

		Password password = (Password) ((CustomField3) event.getTarget().getFellow("pin")).getValue();
		String[]  res;
		try {
			res = svc.parsePkcs12(data, password.getPassword());
		} catch (Exception e) {
			es.caib.zkib.zkiblaf.Missatgebox.info(org.zkoss.util.resource.Labels.getLabel("federacio.zul.wrongPin"));
			return;
		}
		XPathUtils.setValue(this, keyPath, res[0]);
		XPathUtils.setValue(this, publicKeyPath, res[1]);
		XPathUtils.setValue(this, certPath, res[2]);
		Window w = (Window) getFellow("pkcs12");
		w.setVisible(false);
		Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.GeneradoOK"));	
	}
	
	public void addNewKeytab(Event event) {
		FileUpload2.get((ev2) -> {
			UploadEvent ue = (UploadEvent) ev2;
			FederationMember fm = (FederationMember) es.caib.zkib.datasource.XPathUtils.eval(this, "/federationMember");
			new com.soffid.iam.addons.federation.web.KeytabParser().parse(ue.getMedia(), fm);
			((DataNode)es.caib.zkib.datasource.XPathUtils.eval(this, "/")).update();
			getDataSource().sendEvent( new es.caib.zkib.events.XPathRerunEvent(
					getDataSource(), getXPath()+"federationMember/keytabs"));
		});
	}
	
	public void onSelectKeytab (Event ev) {
		DataTable dt = (DataTable) getFellow("keytabsgrid");
		Component b =  getFellow("deleteKeytabButton");
		b.setVisible(dt.getSelectedIndexes().length > 0);
	}

	public void deleteKeytab (Event ev) {
		DataTable dt = (DataTable) getFellow("keytabsgrid");
		dt.deleteSelectedItem();
		Component b =  getFellow("deleteKeytabButton");
		b.setVisible(false);
	}
	
	public void onSelectProfile(Event ev) {
		DataTable dt = (DataTable) getFellow("profilesgrid");
		Window w = (Window) getFellow("profileWindow");
		w.doHighlighted();
		
		SamlProfileEnumeration classe = (SamlProfileEnumeration) XPathUtils.eval(dt, "classe");
		
		if (SamlProfileEnumeration.SAML1_AQ.equals(classe) 
				|| SamlProfileEnumeration.SAML2_AQ.equals(classe)
				|| SamlProfileEnumeration.SAML2_ECP.equals(classe)
				|| SamlProfileEnumeration.SAML2_SSO.equals(classe)) {
			w.getFellow("r_outboundArtifactType").setVisible(true);
			w.getFellow("r_assertionLifetime").setVisible(true);
		} else {
			w.getFellow("r_outboundArtifactType").setVisible(false);
			w.getFellow("r_assertionLifetime").setVisible(false);
		}
		
		if (SamlProfileEnumeration.SAML2_AR.equals(classe)
				|| SamlProfileEnumeration.SAML2_AQ.equals(classe)
				|| SamlProfileEnumeration.SAML2_ECP.equals(classe)
				|| SamlProfileEnumeration.SAML2_SSO.equals(classe)) {
			w.getFellow("r_encryptAssertions").setVisible(true);
			w.getFellow("r_encryptNameIds").setVisible(true);
		} else {
			w.getFellow("r_encryptAssertions").setVisible(false);
			w.getFellow("r_encryptNameIds").setVisible(false);
		}
		
		if (SamlProfileEnumeration.SAML2_AQ.equals(classe)
				|| SamlProfileEnumeration.SAML2_ECP.equals(classe)
				|| SamlProfileEnumeration.SAML2_SSO.equals(classe)) {
			w.getFellow("r_assertionProxyCount").setVisible(true);
		} else {
			w.getFellow("r_assertionProxyCount").setVisible(false);
		}
		
		if (SamlProfileEnumeration.SAML2_ECP.equals(classe)
				|| SamlProfileEnumeration.SAML2_SSO.equals(classe)) {
			w.getFellow("r_includeAttributeStatement").setVisible(true);
		} else {
			w.getFellow("r_includeAttributeStatement").setVisible(false);
		}
		
		if (SamlProfileEnumeration.SAML2_ECP.equals(classe)) {
			w.getFellow("r_localityAddress").setVisible(true);
			w.getFellow("r_localityDNSName").setVisible(true);
		} else {

			w.getFellow("r_localityAddress").setVisible(false);
			w.getFellow("r_localityDNSName").setVisible(false);
		}
		
		if (SamlProfileEnumeration.SAML2_SSO.equals(classe)) {
			w.getFellow("r_maximumSPSessionLifetime").setVisible(true);
		} else {
			w.getFellow("r_maximumSPSessionLifetime").setVisible(false);		
		}
	
		if (SamlProfileEnumeration.OPENID.equals(classe)) {
			w.getFellow("r_discoveryEndpoint").setVisible(true);
			w.getFellow("r_authorizationEndpoint").setVisible(true);
			w.getFellow("r_tokenEndpoint").setVisible(true);
			w.getFellow("r_revokeEndpoint").setVisible(true);
			w.getFellow("r_logoutEndpoint").setVisible(true);
			w.getFellow("r_userinfoEndpoint").setVisible(true);
			w.getFellow("r_signRequests").setVisible(false);
			w.getFellow("r_signAssertions").setVisible(false);
			w.getFellow("r_signResponses").setVisible(false);
			Component form = w.getFellow("form");
			if (XPathUtils.eval(form, "logoutEndpoint") == null) 
				XPathUtils.setValue(form, "logoutEndpoint", "/logout");
			if (XPathUtils.eval(form, "revokeEndpoint") == null) 
				XPathUtils.setValue(form, "revokeEndpoint", "/revoke");
		} else if (SamlProfileEnumeration.CAS.equals(classe)){
			w.getFellow("r_discoveryEndpoint").setVisible(false);
			w.getFellow("r_authorizationEndpoint").setVisible(false);
			w.getFellow("r_tokenEndpoint").setVisible(false);
			w.getFellow("r_revokeEndpoint").setVisible(false);
			w.getFellow("r_logoutEndpoint").setVisible(false);
			w.getFellow("r_userinfoEndpoint").setVisible(false);
			w.getFellow("r_signRequests").setVisible(false);
			w.getFellow("r_signAssertions").setVisible(false);
			w.getFellow("r_signResponses").setVisible(false);
		} else {
			w.getFellow("r_discoveryEndpoint").setVisible(false);
			w.getFellow("r_authorizationEndpoint").setVisible(false);
			w.getFellow("r_tokenEndpoint").setVisible(false);
			w.getFellow("r_revokeEndpoint").setVisible(false);
			w.getFellow("r_logoutEndpoint").setVisible(false);
			w.getFellow("r_userinfoEndpoint").setVisible(false);
			w.getFellow("r_signRequests").setVisible(! SamlProfileEnumeration.RADIUS.equals(classe));
			w.getFellow("r_signAssertions").setVisible(! SamlProfileEnumeration.RADIUS.equals(classe));
			w.getFellow("r_signResponses").setVisible(! SamlProfileEnumeration.RADIUS.equals(classe));
		 }

		w.getFellow("r_radius_authPort").setVisible(SamlProfileEnumeration.RADIUS.equals(classe));
		w.getFellow("r_radius_acctPort").setVisible(SamlProfileEnumeration.RADIUS.equals(classe));
		w.getFellow("r_radius_pap").setVisible(SamlProfileEnumeration.RADIUS.equals(classe));
		w.getFellow("r_radius_chap").setVisible(SamlProfileEnumeration.RADIUS.equals(classe));
		w.getFellow("r_radius_mschap").setVisible(SamlProfileEnumeration.RADIUS.equals(classe));
	}
	
	public void applyProfile(Event ev) {
		Window w = (Window) getFellow("profileWindow");
		Component f = w.getFellow("form");
		if (validateAttributes(f)) {
			DataTable dt = (DataTable) getFellow("profilesgrid");
			dt.setSelectedIndex(-1);
			w.setVisible(false);
		}
		
	}
	
	private boolean validateAttributes(Component form) {
		if (form == null || !form.isVisible()) return true;
		if (form instanceof ObjectAttributesDiv) {
			return ((ObjectAttributesDiv) form).validate();
		}
		if (form instanceof InputField3) {
			InputField3 inputField = (InputField3)form;
			if (inputField.isReadonly() || inputField.isDisabled())
				return true;
			else
				return inputField.attributeValidateAll();
		}
		boolean ok = true;
		for (Component child = form.getFirstChild(); child != null; child = child.getNextSibling())
			if (! validateAttributes(child))
				ok = false;
		return ok;
	}
	
	public void adaptativeUp(Event ev) {
		Component w = getFellow("adaptiveAuthentication");
		Component grid = w.getFellow("grid");
		AuthenticationMethod o = (AuthenticationMethod) XPathUtils.eval(ev.getTarget(), ".");
		LinkedList<AuthenticationMethod> l = (LinkedList<AuthenticationMethod>) XPathUtils.eval(grid, ".");
		int index = l.indexOf(o);
		if (index > 0 )
		{
			l.remove(o);
			l.add(index-1, o);
			es.caib.zkib.binder.BindContext c = XPathUtils.getComponentContext(grid);
			c.getDataSource().sendEvent(new es.caib.zkib.events.XPathRerunEvent(c.getDataSource(), c.getXPath()));
		}
	}

	public void adaptativeDown(Event ev) {
		Component w = getFellow("adaptiveAuthentication");
		Component grid = w.getFellow("grid");
		AuthenticationMethod o = (AuthenticationMethod) XPathUtils.eval(ev.getTarget(), ".");
		LinkedList<AuthenticationMethod> l = (LinkedList<AuthenticationMethod>) XPathUtils.eval(grid, ".");
		int index = l.indexOf(o);
		if (index +1 < l.size() )
		{
			l.remove(o);
			l.add(index+1, o);
			es.caib.zkib.binder.BindContext c = XPathUtils.getComponentContext(grid);
			c.getDataSource().sendEvent(new es.caib.zkib.events.XPathRerunEvent(c.getDataSource(), c.getXPath()));
		}
	}
	
	public void adaptativeRemove(Event ev) {
		Component w = getFellow("adaptiveAuthentication");
		Component grid = w.getFellow("grid");
		AuthenticationMethod o = (AuthenticationMethod) XPathUtils.eval(ev.getTarget(), ".");
		LinkedList<AuthenticationMethod> l = (LinkedList<AuthenticationMethod>) XPathUtils.eval(grid, ".");
		l.remove(o);
		es.caib.zkib.binder.BindContext c = es.caib.zkib.datasource.XPathUtils.getComponentContext(grid);
		c.getDataSource().sendEvent(new es.caib.zkib.events.XPathRerunEvent(c.getDataSource(), c.getXPath()));
	}
	
	public void applyAdaptative(Event ev) {
		Component w = getFellow("adaptiveAuthentication");
		Component grid = w.getFellow("grid");
		w.setVisible(false);
	}

	public void adaptativeAdd(Event ev) throws Exception {
		Component w = getFellow("adaptiveAuthentication");
		Component grid = w.getFellow("grid");
		BindContext bindContext = XPathUtils.getComponentContext(grid);
		XPathUtils.createPath( bindContext.getDataSource(), bindContext.getXPath(), new AuthenticationMethod()); 		
	}
	
	public void serviceProviderSelect (Event ev) {
		DataTable dt = (DataTable) getFellow("serviceprovidersgrid");
		Component deleteButton = dt.getNextSibling().getFirstChild();
		deleteButton.setVisible(dt.getSelectedIndex() >= 0);
	}

	public void serviceProviderDelete (Event ev) {
		DataTable dt = (DataTable) getFellow("serviceprovidersgrid");
		Component deleteButton = dt.getNextSibling().getFirstChild();
		if (dt.getSelectedIndexes() == null || dt.getSelectedIndexes().length == 0) return;
		dt.delete();
		deleteButton.setVisible(false);
	}

	public void serviceProviderAdd (Event ev) throws Exception {
		Window w = (Window) getFellow("serviceProviderWindow");
		DataTable dt = (DataTable) w.getFellowIfAny("serviceprovidersgrid");
		if (dt != null) {
			dt.refresh();
			((Button)w.getFellow("ok")).setDisabled(true);
		}
		w.doHighlighted();
	}

	public void serviceProviderWizardSelect (Event ev) throws Exception {
		((Button)ev.getTarget().getFellow("ok")).setDisabled(false);
	}

	public void serviceProviderWizardBack (Event ev) throws Exception {
		Window w = (Window) getFellow("serviceProviderWindow");
		w.setVisible(false);
	}
	public void serviceProviderWizardNext (Event ev) throws Exception {
		Window w = (Window) getFellow("serviceProviderWindow");
		DataTable dt = (DataTable) w.getFellowIfAny("serviceprovidersgrid");
		FederationMember fm = (FederationMember) XPathUtils.eval(dt, "instance");
		BindContext ctx = XPathUtils.getComponentContext(this);
		XPathUtils.createPath(ctx.getDataSource(), "/federationMember/serviceProvider", fm);
		((DataNode)XPathUtils.eval(this, "/")).update();
		w.setVisible(false);
	}

	@Override
	public void afterCompose() {
		CustomField3 cf = (CustomField3) getFellow("id_registerWorkflow");
		List<String> w = new LinkedList<>();
		try {
			for (ProcessDefinition bpm: EJBLocator.getBpmEngine().findProcessDefinitions(null, true)) {
				w.add(bpm.getName());
			}
			cf.setValues(w);
		} catch (Exception e) {
		}
		if (w.isEmpty())
			cf.setVisible(false);
		else
			cf.updateMetadata();
		
	}

}
