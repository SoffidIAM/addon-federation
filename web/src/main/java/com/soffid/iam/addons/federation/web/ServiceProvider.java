package com.soffid.iam.addons.federation.web;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;

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
import org.zkoss.zul.Filedownload;
import org.zkoss.zul.Window;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.api.Password;
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

public class ServiceProvider extends Form2 implements XPathSubscriber, AfterCompose {

	private String certPath;
	private String publicKeyPath;
	private String keyPath;
	private byte[] data;

	ProviderHandler getFrame() {
		return (ProviderHandler) getPage().getFellow("frame");
	}
	
	public void onChangeType (Event event) {
		enableSPComponents();
	}
	
	public void enableSPComponents ()
	{
		ServiceProviderType spType = (ServiceProviderType) es.caib.zkib.datasource.XPathUtils.eval(this, "/federationMember/serviceProviderType");
		getFellow("networkSection").setVisible(spType == ServiceProviderType.SOFFID_SAML);
		getFellow("certificateSection").setVisible(spType == ServiceProviderType.SOFFID_SAML);
		getFellow("openidSection").setVisible(spType == ServiceProviderType.OPENID_CONNECT);
//		((CustomField3)getFellow("organization")).setVisible(ServiceProviderType.OPENID_CONNECT != spType);
//		((CustomField3)getFellow("organization")).setReadonly(ServiceProviderType.SOFFID_SAML != spType);
//		((CustomField3)getFellow("contact")).setVisible(ServiceProviderType.OPENID_CONNECT != spType);
//		((CustomField3)getFellow("contact")).setReadonly(ServiceProviderType.SOFFID_SAML != spType);

		((CustomField3)getFellow("metadades")).setVisible(spType != ServiceProviderType.OPENID_CONNECT);
		((CustomField3)getFellow("metadades")).setDisabled(spType != ServiceProviderType.SAML);
		((CustomField3)getFellow("oauthKey")).setVisible(spType == ServiceProviderType.OPENID_CONNECT);
		((CustomField3)getFellow("oauthSecret")).setVisible(spType == ServiceProviderType.OPENID_CONNECT);
		((CustomField3)getFellow("contact")).setVisible(spType == ServiceProviderType.SOFFID_SAML);
		((CustomField3)getFellow("organization")).setVisible(spType == ServiceProviderType.SOFFID_SAML);
	}	

	public void onChangeName(Event event) {
		XPathUtils.setValue(this, "description",  XPathUtils.eval(this, "federationMember/publicId"));
		generateMetadata();
	}
	
	public void changeMetadata(Event event) throws ParserConfigurationException, SAXException, IOException {
        try {
        	CustomField3 md = (CustomField3) event.getTarget();
        	CustomField3 publicid = (CustomField3) getFellow("idpPublicId");;
        	
        	ServiceProviderType idpType = (ServiceProviderType) es.caib.zkib.datasource.XPathUtils.eval(this, "/federationMember/serviceProviderType");
        	if (idpType.equals( ServiceProviderType.SAML) )
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
                    	}
                    }
                }
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
			if ( "SP".equals(type)) {
				enableSPComponents();
				updateOpenidMechanismListbox();
			}
		} catch (Exception e) {}
	}
	
	public void updateOpenidMechanism() {
		Collection<String> s = (Collection<String>) XPathUtils.eval(this, "/federationMember/openidMechanism");
		if (s == null)
			s = new HashSet<>();
		s.clear();

		if ( Boolean.TRUE.equals( ((CustomField3)getFellow("oid_implicit")).getValue()))
			s.add("IM");

		if ( Boolean.TRUE.equals( ((CustomField3)getFellow("oid_authcode")).getValue()))
			s.add("AC");

		if ( Boolean.TRUE.equals( ((CustomField3)getFellow("oid_password")).getValue()))
			s.add("PA");
		
		if ( Boolean.TRUE.equals( ((CustomField3)getFellow("oid_passsword_clientcred")).getValue()))
			s.add("PC");
		
		DataNode dn = (DataNode) XPathUtils.eval(this, "/");
		dn.update();
	}

	void updateOpenidMechanismListbox() {
		Collection<String> s = (Collection<String>) XPathUtils.eval(this, "/federationMember/openidMechanism");
		if (s == null) s = new LinkedList<>();
		((CustomField3)getFellow("oid_implicit")).setValue(s.contains("IM"));
		((CustomField3)getFellow("oid_authcode")).setValue(s.contains("AC"));
		((CustomField3)getFellow("oid_password")).setValue(s.contains("PA"));
		((CustomField3)getFellow("oid_passsword_clientcred")).setValue(s.contains("PC"));
	}

	
	public void generateKey(Event ev) throws InternalErrorException, NamingException {
		generateKeys("/federationMember/privateKey", "/federationMember/publicKey", "/federationMember/certificateChain", "/federationMember/publicId");
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
		generateMetadata();
		Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.GeneradoOK"));	
	}

	public void deleteKey(Event ev) throws InternalErrorException, NamingException {
		deleteKeys("/federationMember/privateKey", "/federationMember/publicKey", "/federationMember/certificateChain", "/federationMember/publicId");
	}

	private void deleteKeys(String keyPath, String publicKeyPath, String certPath, String namePath) throws InternalErrorException, NamingException {
		XPathUtils.setValue(this, publicKeyPath, null);
		XPathUtils.setValue(this, keyPath, null);
		XPathUtils.setValue(this, certPath, null);
		generateMetadata();
		Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.BorratOK"));	
	}
	
	public void generatePKCS10(Event ev) throws InternalErrorException, NamingException {
		generatePkcs10("/federationMember/privateKey", "/federationMember/publicKey", "/federationMember/certificateChain", "/federationMember/publicId");
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
		XPathUtils.setValue(this, publicKeyPath, res[0]);
		XPathUtils.setValue(this, keyPath, res[1]);
		XPathUtils.setValue(this, certPath, res[2]);
		Window w = (Window) getFellow("pkcs12");
		w.setVisible(false);
		generateMetadata();
		Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.GeneradoOK"));	
	}
	

	@Override
	public void afterCompose() {
		CustomField3 cf = (CustomField3) getFellow("uidScript");

		StringBuffer sb = new StringBuffer();
		sb.append("{\"serverService\":\"es.caib.seycon.ng.sync.servei.ServerService\","
				+ "\"remoteServiceLocator\":\"es.caib.seycon.ng.remote.RemoteServiceLocator\","
				+ "\"serviceLocatorV1\":\"es.caib.seycon.ng.ServiceLocator\","
				+ "\"serviceLocator\":\"com.soffid.iam.ServiceLocator\"");

		sb.append(", \"accountId\" : \"java.lang.Long\"")
			.append(", \"accountName\" : \"java.lang.String\"")
			.append(", \"system\" : \"java.lang.String\"")
			.append(", \"accountDescription\" : \"java.lang.String\"")
			.append(", \"accountDisabled\" : \"java.lang.String\"")
			.append(", \"active\" : \"java.lang.Boolean\"")
			.append(", \"mailAlias\" : \"java.lang.String\"")
			.append(", \"userName\" : \"java.lang.String\"")
			.append(", \"primaryGroup\" : \"java.lang.String\"")
			.append(", \"comments\" : \"java.lang.String\"")
			.append(", \"createdOn\" : \"java.util.Calendar\"")
			.append(", \"modifiedOn\" : \"java.util.Calendar\"")
			.append(", \"mailDomain\" : \"java.lang.String\"")
			.append(", \"fullName\" : \"java.lang.String\"")
			.append(", \"id\" : \"java.lang.Long\"")
			.append(", \"multiSession\" : \"java.lang.Boolean\"")
			.append(", \"firstName\" : \"java.lang.String\"")
			.append(", \"shortName\" : \"java.lang.String\"")
			.append(", \"lastName\" : \"java.lang.String\"")
			.append(", \"lastName2\" : \"java.lang.String\"")
			.append(", \"mailServer\" : \"java.lang.String\"")
			.append(", \"homeServer\" : \"java.lang.String\"")
			.append(", \"profileServer\" : \"java.lang.String\"")
			.append(", \"phone\" : \"java.lang.String\"")
			.append(", \"userType\" : \"java.lang.String\"")
			.append(", \"createdBy\" : \"java.lang.String\"")
			.append(", \"modifiedBy\" : \"java.lang.String\"")
			.append(", \"primaryGroupObject\" : \"groupObject\"")
			.append(", \"secondaryGroups\" : \"list<groupObject>\"")
			.append(", \"accountAttributes\" : \"accountAttributes\"")
			.append(", \"userAttributes\" : \"userAttributes\"")
			.append(", \"attributes\" : \"userAttributes\"") 
			.append(", \"grantedRoles\" : \"list<grantObject>\"")
			.append(", \"allGrantedRoles\" : \"list<grantObject>\"")
			.append(", \"granted\" : \"list<grantObject>\"")
			.append(", \"allGranted\" : \"list<grantObject>\"");
		sb.append("}");
		
		cf.setJavascript(sb.toString());
	}
	
	public void generateMetadata() {
		ServiceProviderType spType = (ServiceProviderType) es.caib.zkib.datasource.XPathUtils.eval(this, "/federationMember/serviceProviderType");
		if (spType != ServiceProviderType.SOFFID_SAML) return;
		
		
		String formPublicId = (String) XPathUtils.eval(this, "/federationMember/publicId");
		String formHostName = (String) XPathUtils.eval(this, "/federationMember/hostName");
		String formStandardPort = (String) XPathUtils.eval(this, "/federationMember/standardPort");
		String formAssertionPath = (String) XPathUtils.eval(this, "/federationMember/assertionPath");

		// Review if we have all the needed data
		boolean missingData = false;
		if (formPublicId==null || formPublicId.isEmpty()) {
			missingData = true;
		} else if (formHostName==null || formHostName.isEmpty()) {
			missingData = true;
		} else if (formStandardPort==null || formStandardPort.isEmpty()) {
			missingData = true;
		} else if (formAssertionPath==null || formAssertionPath.isEmpty()) {
			missingData = true;
		}

		// Clean or build the metadata attribute
		if (missingData == true) {
			XPathUtils.setValue(this, "/federationMember/metadades",  "");
		} else {

			// Optionally, we can include the certificate chain
			String formCertificateChain = (String) XPathUtils.eval(this,  "/federationMember/certificateChain");
			String myCertificate = "";
			if (formCertificateChain!=null && !formCertificateChain.isEmpty()){
				formCertificateChain = formCertificateChain.trim();
				int i = formCertificateChain.indexOf("-----BEGIN CERTIFICATE-----");
				if (i >= 0)
				{
					int j = formCertificateChain.indexOf("-----END CERTIFICATE-----", i);
					if (j > 0)
					{
						StringBuffer plantilla = new StringBuffer();
						plantilla.append("		<KeyDescriptor>\n");
						plantilla.append("			<ds:KeyInfo>\n");
						plantilla.append("				<ds:KeyName>defaultKey</ds:KeyName>\n");
						plantilla.append("				<ds:X509Data>\n");
						plantilla.append("					<ds:X509Certificate>\n");
						plantilla.append(formCertificateChain.substring(i+28, 
							j));
						plantilla.append("					</ds:X509Certificate>\n");
						plantilla.append("				</ds:X509Data>\n");
						plantilla.append("			</ds:KeyInfo>\n");
						plantilla.append("		</KeyDescriptor>\n");
						myCertificate = plantilla.toString();
					}
				}
			}

			// Optionally, the SSL check could be checked to be disabled
			Boolean formDisableSSL = (Boolean) XPathUtils.eval(this, "/federationMember/disableSSL");
			String myProtocol = "https";
			if (formDisableSSL!=null && formDisableSSL.booleanValue()==true) {
				myProtocol = "http";
			}

			// Generate the xml metadata
			StringBuffer plantilla = new StringBuffer();
			plantilla.append("<EntityDescriptor entityID=\""+formPublicId+"\"\n");
			plantilla.append("		xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"\n");
			plantilla.append("		xmlns:alg=\"urn:oasis:names:tc:SAML:metadata:algsupport\"\n");
			plantilla.append("      xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n");
			plantilla.append("  <Extensions>\n");
			plantilla.append("	    <alg:DigestMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'/>\n");
			plantilla.append("	</Extensions>\n");
			plantilla.append("	<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n");
			if (!myCertificate.isEmpty()) plantilla.append(myCertificate);
			plantilla.append("		<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>\n");
			plantilla.append("		<AssertionConsumerService index=\"1\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n");
			plantilla.append("			Location=\""+myProtocol+"://"+formHostName+":"+formStandardPort+"/"+formAssertionPath+"\">\n");
			plantilla.append("		</AssertionConsumerService>\n");
			plantilla.append("	</SPSSODescriptor>\n");
			plantilla.append("</EntityDescriptor>");
			XPathUtils.setValue(this, "/federationMember/metadades",  plantilla.toString());
		}
	}

}
