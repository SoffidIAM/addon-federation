package com.soffid.iam.addons.federation.web;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.zkoss.util.media.Media;
import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.UploadEvent;
import org.zkoss.zul.Filedownload;
import org.zkoss.zul.Window;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SubjectSourceEnumeration;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.api.Password;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.component.FrameHandler;
import com.soffid.iam.web.component.InputField3;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.signatura.utils.Base64;
import es.caib.zkib.component.Wizard;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.jxpath.JXPathException;
import es.caib.zkib.zkiblaf.Missatgebox;

public class SseHandler extends FrameHandler {

	private static final String IDP_QUERY = "idpType eq 'soffid' or idpType eq 'soffid-cloud'";
	private byte[] data;
	private String keyPath;
	private String publicKeyPath;
	private String certPath;

	public SseHandler() throws InternalErrorException {
		super();
	}

	@Override
	public void onChangeForm(Event ev) throws Exception {
		super.onChangeForm(ev);
		try {
			Digest p = (Digest) es.caib.zkib.datasource.XPathUtils.eval(getForm(), "token");
	
			final InputField3 token = (InputField3) getFellow("token");
			token.setValue(p == null? "": "****");
			changeSourceType(ev);
		} catch (JXPathException e) {}
	}

	public void changeSourceType(Event ev) {
		SubjectSourceEnumeration type = (SubjectSourceEnumeration) XPathUtils.eval(getForm(), "sourceType");
		getFellow("sourceOAuth").setVisible(type == SubjectSourceEnumeration.OAUTH_ATTRIBUTE);
		getFellow("sourceExpression").setVisible(type == SubjectSourceEnumeration.EXPRESSION);
		getFellow("system").setVisible(type == SubjectSourceEnumeration.SYSTEM);
	}

	public void clearOpenidSecret(Event ev) throws NoSuchAlgorithmException {
		Digest secret = (Digest) es.caib.zkib.datasource.XPathUtils.eval(getForm(), "token");
		if (secret != null) {
			Missatgebox.confirmaYES_NO(Labels.getLabel("federacio.zul.confirmEmptySecret"), (ev2) -> {
				if (ev2.getName().equals("onYes")) {
					es.caib.zkib.datasource.XPathUtils.setValue(getForm(), "token", null);
					final InputField3 token = (InputField3) getFellow("token");
					token.setValue("");
				}
			});
		}
	}
	
	public void generateOpenidSecret(Event ev) throws NoSuchAlgorithmException {
		Digest secret = (Digest) es.caib.zkib.datasource.XPathUtils.eval(getForm(), "token");
		if (secret == null)
			generateNewSecret();
		else 
			Missatgebox.confirmaYES_NO(Labels.getLabel("federacio.zul.confirmNewSecret"), (ev2) -> {
				if (ev2.getName().equals("onYes")) {
					generateNewSecret();
				}
			});
	}
	
	private void generateNewSecret() throws NoSuchAlgorithmException {
		byte b[] = new byte[36];
		new SecureRandom().nextBytes(b);
		String sb = Base64.encodeBytes(b, Base64.DONT_BREAK_LINES);
		
		es.caib.zkib.datasource.XPathUtils.setValue(getForm(), 
				"token",
				new Digest(sb));
		final InputField3 token = (InputField3) getFellow("token");
		token.setValue("Bearer "+sb);
	}
	
	public void generateSslKey(Event ev) throws InternalErrorException, NamingException {
		generateKeys("/sslKey", "/sslPublicKey", "/sslCertificate");
		
	}

	public void generateKeys(String keyPath, String publicKeyPath, String certPath) throws InternalErrorException, NamingException {
		String key = (String) XPathUtils.eval(getListbox(), keyPath) ;
		if (key != null) {
			Missatgebox.confirmaYES_NO(
					org.zkoss.util.resource.Labels.getLabel("federacio.SegurCanvi"),
					org.zkoss.util.resource.Labels.getLabel("federacio.Confirmacio"),
					(event) -> {
						if (event.getName().equals("onYes"))
							doGenerateKeys (keyPath, publicKeyPath, certPath);
					}
			);
		} else
		{
			doGenerateKeys (keyPath, publicKeyPath, certPath);
		}
	}
	
	private void doGenerateKeys(String keyPath, String publicKeyPath, String certPath) throws InternalErrorException, NamingException {
		FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);

		for (FederationMember fm: svc.findFederationMembersByJsonQuery(
				null,
				IDP_QUERY,null,null)
				.getResources()) {
			String[] res = svc.generateKeys( fm.getPublicId() );
		
			XPathUtils.setValue(getListbox(), publicKeyPath, res[0]);
			XPathUtils.setValue(getListbox(), keyPath, res[1]);
			XPathUtils.setValue(getListbox(), certPath, res[2]);
			Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.GeneradoOK"));	
			break;
		}
	}

	public void deleteSslKey(Event ev) throws InternalErrorException, NamingException {
		deleteKeys("/sslKey", "/sslPublicKey", "/sslCertificate");
	}

	private void deleteKeys(String keyPath, String publicKeyPath, String certPath) throws InternalErrorException, NamingException {
		XPathUtils.setValue(getListbox(), publicKeyPath, null);
		XPathUtils.setValue(getListbox(), keyPath, null);
		XPathUtils.setValue(getListbox(), certPath, null);
		Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.BorratOK"));	
	}
	
	public void generateSslPKCS10(Event ev) throws InternalErrorException, NamingException {
		generatePkcs10("/sslKey", "/sslPublicKey", "/sslCertificate");
	}

	private void generatePkcs10(String keyPath, String publicKeyPath, String certPath) throws InternalErrorException, NamingException {
		String priv = (String) XPathUtils.eval(getListbox(), keyPath);
		String pub = (String) XPathUtils.eval(getListbox(), publicKeyPath);
		
		if (priv !=null && ! priv.trim().isEmpty()) {
			FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			for (FederationMember fm: svc.findFederationMembersByJsonQuery(
					null,
					IDP_QUERY,null,null)
					.getResources()) {
				String res = svc.generatePKCS10(fm, priv, pub);
				
				org.zkoss.util.media.AMedia pkcs = new org.zkoss.util.media.AMedia(
						(String) XPathUtils.eval(getListbox(), "name"),
						"txt","binary/octet-stream",res);
				Filedownload.save(pkcs);
			}
		}
	}

	public void uploadSslPkcs12(Event ev) throws InternalErrorException, NamingException {
		uploadPkcs12("/sslKey", "sslPublicKey", "/sslCertificate");
	}

	private void uploadPkcs12(String keyPath, String pubkeyPath, String certPath) throws InternalErrorException, NamingException {
		this.keyPath = keyPath;
		this.publicKeyPath = pubkeyPath;
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
		XPathUtils.setValue(getListbox(), keyPath, res[0]);
		XPathUtils.setValue(getListbox(), publicKeyPath, res[1]);
		XPathUtils.setValue(getListbox(), certPath, res[2]);
		Window w = (Window) getFellow("pkcs12");
		w.setVisible(false);
		Missatgebox.info (org.zkoss.util.resource.Labels.getLabel("federacio.GeneradoOK"));	
	}

	@Override
	public void afterCompose() {
		super.afterCompose();
		List<String> list = new LinkedList<>();
		FederationService svc;
		try {
			svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			for (FederationMember fm: svc.findFederationMembersByJsonQuery(null, 
					"idpType eq 'soffid' or idpType eq 'soffid-cloud'", null, null)
					.getResources()) {
				list.add(URLEncoder.encode(fm.getPublicId(),"UTF-8")+":"+fm.getName()+ " "+fm.getPublicId());
			}
			CustomField3 cf = (CustomField3) getFellow("identityProvider");
			cf.setValues(list);
			cf.createField();
		} catch (Exception e) {
		}
		try {
			list.clear();
			svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			for (FederationMember fm: svc.findFederationMembersByJsonQuery(null, 
					"serviceProviderType eq 'openid-connect'", null, null)
					.getResources()) {
				list.add(URLEncoder.encode(fm.getPublicId(),"UTF-8")+":"+fm.getName()+ " "+fm.getPublicId());
			}
			CustomField3 cf = (CustomField3) getFellow("serviceProvider");
			cf.setValues(list);
			cf.createField();
		} catch (Exception e) {
		}
	}
	

}
