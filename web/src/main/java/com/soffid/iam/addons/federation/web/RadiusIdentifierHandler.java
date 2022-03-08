package com.soffid.iam.addons.federation.web;

import com.soffid.iam.web.component.InputField3;
import com.soffid.iam.web.component.InputFieldUIHandler;

public class RadiusIdentifierHandler extends InputFieldUIHandler {

	@Override
	public boolean validate(InputField3 field) throws Exception {
		String value = (String) field.getValue();
		if (value == null || value.trim().isEmpty())
			return true;
		int dot = value.indexOf('.');
		if (dot < 0) {
			try {
				Integer.parseInt(value);
			} catch (NumberFormatException e) {
				field.setWarning(null, "The Radius identifier must be an integer number. For vendor specific attributes, it must have the form [vendor-id].[attribute-id]");
				return false;
			}
		} else {
			try {
				Integer.parseInt(value.substring(0, dot));
			} catch (NumberFormatException e) {
				field.setWarning(null, "Cannot parse the vendor id. The radius identifier must have the form [vendor-number].[attribute-number]");
				return false;
			}
			try {
				Integer.parseInt(value.substring(dot+1));
			} catch (NumberFormatException e) {
				field.setWarning(null, "Cannot parse the attribute number. The radius identifier must have the form [vendor-number].[attribute-number]");
				return false;
			}
		}
		return super.validate(field);
	}

}
