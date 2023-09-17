package com.soffid.iam.addons.federation.web;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.zkoss.util.media.AMedia;
import org.zkoss.util.media.Media;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.UploadEvent;
import org.zkoss.zul.Filedownload;
import org.zkoss.zul.Window;

import com.soffid.iam.addons.federation.common.RootCertificate;
import com.soffid.iam.web.component.FrameHandler;
import com.soffid.iam.web.component.InputField3;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;
import es.caib.zkib.component.Wizard;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.jxpath.JXPathException;

public class RootCertificateHandler extends FrameHandler {

	private Object type;
	private X509Certificate cert;

	public RootCertificateHandler() throws InternalErrorException {
		super();
	}
	
	public void addNew(Event event) {
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		wizard.setSelected(0);
		((InputField3)w.getFellow("type")).setValue("internal");
		w.doHighlighted();
	}

	public void addStep2(Event event) {
		Window w = (Window) getFellow("add-window");
		type = ((InputField3)w.getFellow("type")).getValue();
		w.getFellow("upload").setVisible("external".equals(type));
		w.getFellow("generate").setVisible("internal".equals(type));
		if (type.equals("internal")) {
			InputField3 ed = (InputField3) w.getFellow("expirationDate");
			Calendar c = Calendar.getInstance();
			c.add(Calendar.YEAR, 10);
			ed.setValue(c.getTime());
			InputField3 month = (InputField3) w.getFellow("userCertificateMonths");
			month.setValue(24);
		}
		Wizard wizard = (Wizard) w.getFellow("wizard");
		wizard.next();
	}

	public void addStep1(Event event) {
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		wizard.previous();
	}
	
	public void addUndo(Event event) {
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		if (wizard.getSelected() == 0)
			w.setVisible(false);
		else
			wizard.previous();
	}
	
	public void onUpload(UploadEvent evnt) throws IOException {
		Media media = evnt.getMedia();
		if (media != null) {
			byte [] data;
			if (media.isBinary() ) {
				if (media.inMemory())
					data = media.getByteData();
				else {
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					InputStream in = media.getStreamData();
					for (int read = in.read(); read >= 0; read = in.read()) {
						out.write(read);
					}
					data = out.toByteArray();
				}
			} else {
				if (media.inMemory())
					data = media.getStringData().getBytes("UTF-8");
				else {
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					OutputStreamWriter w = new OutputStreamWriter(out, "UTF-8");
					Reader in = media.getReaderData();
					for (int read = in.read(); read >= 0; read = in.read())
						out.write(read);
					data = out.toByteArray();
				}
			}
			
			cert = null;
			try {
				cert = readPem(data);
			} catch(Exception e) {};
			try {
				if (cert == null)
					cert = readBase64(data);
			} catch(Exception e) {};
			try {
				if (cert == null)
					cert = readDer(data);
			} catch(Exception e) {};
			
			Window w = (Window) getFellow("add-window");
			InputField3 s = (InputField3) w.getFellow("guessScript");
			InputField3 o = (InputField3) w.getFellow("organizationName2");
			if (cert == null) {
				o.setValue("");
				s.setWarning(0, "Please, upload the root certifiate");
			} else {
				String name = cert.getSubjectX500Principal().getName();
				if (name.length() > 100)
					name = name.substring(0, 100);
				o.setValue(name);
				s.setWarning(0, "");
			}
				
		}
	}

	private X509Certificate readPem(byte[] data) throws CertificateException, IOException {
		String s = new String(data, "UTF-8");
		PemReader reader = new PemReader(new StringReader(s));
		PemObject obj = reader.readPemObject();
		if (obj != null && obj.getType().equals("CERTIFICATE")) {
			return readDer(obj.getContent());
		}
		return null;
	}

	private X509Certificate readBase64(byte[] data) throws CertificateException, UnsupportedEncodingException {
		byte[] decoded = Base64.decode(new String(data, "UTF-8"));
		return readDer(decoded);
	}

	private X509Certificate readDer(byte[] data) throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream in = new ByteArrayInputStream(data);
		return (X509Certificate) cf.generateCertificate(in);
	}
	
	public void addApply(Event event) throws Exception {
		Window w = (Window) getFellow("add-window");
		type = ((InputField3)w.getFellow("type")).getValue();
		if ("external".equals(type)) {
			InputField3 o = (InputField3) w.getFellow("organizationName2");
			InputField3 s = (InputField3) w.getFellow("guessScript");
			InputField3 d = (InputField3) w.getFellow("device2");
			if (cert == null) {
				s.setWarning(0, "Please, upload the root certifiate");
			} else {
				RootCertificate rc = new RootCertificate();
				rc.setCertificate(cert);
				Calendar c = Calendar.getInstance();
				rc.setCreationDate(c);
				c = Calendar.getInstance();
				c.setTime(cert.getNotAfter());
				rc.setExpirationDate(c);
				rc.setExternal(true);
				rc.setGuessUserScript((String) s.getValue());
				rc.setObsolete(false);
				rc.setOrganizationName((String) o.getValue());
				rc.setDevice(Boolean.TRUE.equals(d.getValue()));
				String path = XPathUtils.createPath(getModel(), "/certificate", rc);
				try {
					getModel().commit();
					w.setVisible(false);
				} catch (Exception e) {
					XPathUtils.removePath(getModel(), path);
					throw e;
				}
			}
		} else {
			InputField3 ed = (InputField3) w.getFellow("expirationDate");
			InputField3 o = (InputField3) w.getFellow("organizationName");
			InputField3 month = (InputField3) w.getFellow("userCertificateMonths");
			InputField3 d = (InputField3) w.getFellow("device3");
			if (ed.attributeValidateAll() && o.attributeValidateAll() && month.attributeValidateAll()) {
				RootCertificate rc = new RootCertificate();
				Calendar c = Calendar.getInstance();
				rc.setCreationDate(c);
				c = Calendar.getInstance();
				c.setTime((Date)ed.getValue());
				rc.setExpirationDate(c);
				rc.setExternal(false);
				rc.setObsolete(false);
				rc.setOrganizationName((String) o.getValue());
				rc.setUserCertificateMonths( Integer.parseInt(month.getValue().toString()));
				rc.setDevice(Boolean.TRUE.equals(d.getValue()));
				String path = XPathUtils.createPath(getModel(), "/certificate", rc);
				try {
					getModel().commit();
					w.setVisible(false);
				} catch (Exception e) {
					XPathUtils.removePath(getModel(), path);
					throw e;
				}
				
			}
		}
		
	}

	public void downloadCert(Event ev) throws CertificateEncodingException, InvalidNameException {
		X509Certificate cert = (X509Certificate) XPathUtils.eval(getForm(), "certificate");
		if (cert != null) {
			LdapName name = new LdapName(cert.getSubjectX500Principal().getName());
			String n = (String) name.getRdn(name.getRdns().size()-1).getValue();
			Filedownload.save(new AMedia(n+".crt", null, "application/x-x509-ca-cert",  cert.getEncoded()));
		}
				
	}
	@Override
	public void onChangeForm(Event ev) throws Exception {
		super.onChangeForm(ev);
		try {
			Boolean external = (Boolean) XPathUtils.eval(getForm(), "external");
			getFellow("userCertificateMonths").setVisible(Boolean.FALSE.equals(external));
			getFellow("guessUserScript").setVisible(Boolean.TRUE.equals(external));
			
		} catch(JXPathException e) {}
	}
}
