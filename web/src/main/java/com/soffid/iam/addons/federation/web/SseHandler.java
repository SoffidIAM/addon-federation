package com.soffid.iam.addons.federation.web;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.event.Event;

import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.web.component.FrameHandler;
import com.soffid.iam.web.component.InputField3;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.signatura.utils.Base64;
import es.caib.zkib.jxpath.JXPathException;
import es.caib.zkib.zkiblaf.Missatgebox;

public class SseHandler extends FrameHandler {

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
		} catch (JXPathException e) {}
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
}
