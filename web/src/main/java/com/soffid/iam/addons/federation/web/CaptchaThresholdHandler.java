package com.soffid.iam.addons.federation.web;

import com.soffid.iam.web.component.InputField3;
import com.soffid.iam.web.component.InputFieldUIHandler;

import es.caib.zkib.datasource.XPathUtils;

public class CaptchaThresholdHandler extends InputFieldUIHandler {

	@Override
	public boolean validate(InputField3 field) throws Exception {
		boolean enabled = Boolean.TRUE.equals( XPathUtils.eval(field.getParent(), "/federationMember/enableCaptcha") );
		if (!enabled) return true;
		
		Object value = field.getValue();
		if (value == null || value.toString().trim().isEmpty()) { 
			field.setWarning(0, "Please, enter a value");
			return false;
		}
		
		double v = Double.parseDouble(value.toString());
		if (v < 0 || v > 1) {
			field.setWarning(0, "Please, enter a value between 0 and 1");
			return false;
		}
		return super.validate(field);
	}

}
