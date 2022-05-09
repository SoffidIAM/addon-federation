package com.soffid.iam.addons.federation.web;

import java.net.URI;
import java.util.LinkedList;
import java.util.Random;

import javax.naming.InitialContext;

import org.zkoss.util.media.AMedia;
import org.zkoss.util.resource.Labels;
import org.zkoss.zk.au.out.AuScript;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.Path;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zul.Filedownload;
import org.zkoss.zul.Label;
import org.zkoss.zul.Textbox;
import org.zkoss.zul.Window;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.service.ejb.SelfCertificateService;
import com.soffid.iam.addons.federation.service.ejb.SelfCertificateServiceHome;
import com.soffid.iam.addons.federation.service.ejb.UserCredentialService;
import com.soffid.iam.addons.federation.service.ejb.UserCredentialServiceHome;
import com.soffid.iam.utils.Security;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.component.FrameHandler;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;
import es.caib.zkib.component.DataModel;
import es.caib.zkib.component.DataTable;
import es.caib.zkib.component.Wizard;
import es.caib.zkib.datamodel.DataModelCollection;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.zkiblaf.Missatgebox;

public class UserTokenHandler extends FrameHandler {
	public UserTokenHandler() throws InternalErrorException {
		super();
	}
	String parentPath;
	String model;

	public String getParentPath() {
		return parentPath;
	}

	public void setParentPath(String parentPath) {
		this.parentPath = parentPath;
	}

	@Override
	protected DataModel getModel() {
		return (DataModel) Path.getComponent(getPage(), model);
	}

	public void setModel(String model) {
		this.model = model;
	}
	
	public DataTable getParentListbox() {
		return (DataTable) Path.getComponent(getPage(), parentPath);
	}
	
	public void refresh() throws Exception {
		DataModelCollection coll = (DataModelCollection) XPathUtils.eval(getParentListbox(), "/token");
		DataTable dt = (DataTable) getListbox();
		if (dt.getSelectedIndexes().length == 0)
			coll.refresh();
	}
	
	public void changeType(Event ev) {
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		String type = (String) ((CustomField3)w.getFellow("type")).getValue();
		((CustomField3)w.getFellow("description")).setVisible("cert".equals(type));
	}
	
	@Override
	public void addNew() throws Exception {
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		wizard.setSelected(0);
		w.doHighlighted();
		final CustomField3 typeField = (CustomField3)w.getFellow("type");
		typeField.setWarning(0, "");
		java.util.List<String> values = new LinkedList<>();
		if ( Security.isUserInRole("federation:token:user"))
			values.add("fido: "+Labels.getLabel("com.soffid.iam.addons.federation.common.UserCredentialType.FIDO"));
		if ( Security.isUserInRole("federation:certificate:user"))
			values.add("cert: "+Labels.getLabel("com.soffid.iam.addons.federation.common.UserCredentialType.CERT"));
		typeField.setValues(values);
		typeField.updateMetadata();
	}
	
	public void addUndo() throws Exception {
		Window w = (Window) getFellow("add-window");
		w.setVisible(false);
		refresh();
	}

	public void addApply() throws Exception {
		Window w = (Window) getFellow("add-window");
		Wizard wizard = (Wizard) w.getFellow("wizard");
		final CustomField3 typeField = (CustomField3)w.getFellow("type");
		if (typeField.attributeValidateAll()) {
			String type = (String) typeField.getValue();
			String user = (String) XPathUtils.eval(getParentListbox(), "/userName");
			if ("fido".equals(type)) {
				if ( ! Security.isUserInRole("federation-credential:create")) {
					typeField.setWarning(0, "Not authorized");
					return;
				}
				w.getFellow("forFido").setVisible(true);
				w.getFellow("forcert").setVisible(false);
				UserCredentialService ejb = (UserCredentialService) new InitialContext().lookup(UserCredentialServiceHome.JNDI_NAME);
				
				URI uri = ejb.generateNewCredential(user);
				
				((Label)w.getFellow("fidoinstructions")).setValue(Labels.getLabel("federation.token.urlmessage"));
				Label l = (Label) w.getFellow("password");
				l.setValue(uri.toString());
				((Textbox)w.getFellow("qpassword")).setValue(uri.toString());
				wizard.next();
			} else {
				if ( ! Security.isUserInRole("selfcertificate:create")) {
					typeField.setWarning(0, "Not authorized");
					return;
				}
				final CustomField3 descField = (CustomField3)w.getFellow("description");
				if (descField.attributeValidateAll()) {
					w.getFellow("forFido").setVisible(false);
					w.getFellow("forcert").setVisible(true);
					SelfCertificateService ejb = (SelfCertificateService) new InitialContext().lookup(SelfCertificateServiceHome.JNDI_NAME);
					byte b[] = new byte[6];
					new Random().nextBytes(b);
					final String description = (String)descField.getValue();
					String password = Base64.encodeBytes(b);
					byte[] r = ejb.createPkcs12(user, description, password);
					refresh();
					Label l = (Label) w.getFellow("password");
					l.setValue(password);
					((Textbox)w.getFellow("qpassword")).setValue(password);
					wizard.next();
					AMedia m = new AMedia(description+".p12", "pkcs12", "application/x-pkcs12", r);
					Filedownload.save(m);
				}
			}
		}
	}

}
