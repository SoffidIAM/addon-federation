package com.soffid.iam.addons.federation.web;

import com.soffid.iam.web.component.InputField3;
import com.soffid.iam.web.component.InputFieldUIHandler;

import es.caib.zkib.datasource.XPathUtils;

public class CaptchaKeyHandler extends InputFieldUIHandler {

	@Override
	public boolean validate(InputField3 field) throws Exception {
		boolean enabled = Boolean.TRUE.equals( XPathUtils.eval(field.getParent(), "/federationMember/enableCaptcha") );
		if (!enabled) return true;
		
		Object value = field.getValue();
		if (value == null || value.toString().trim().isEmpty()) { 
			field.setWarning(0, "Enter your reCaptcha site key. You can get it at: https://www.google.com/recaptcha/admin/create");
			return false;
		}
		
		return super.validate(field);
	}

}
