package com.soffid.iam.addons.federation.web;

import com.soffid.iam.web.component.InputField3;
import com.soffid.iam.web.component.InputFieldUIHandler;

public class ProgressiveForm extends InputFieldUIHandler {

	@Override
	public boolean openSelectWindow(InputField3 field) throws Exception {
		com.soffid.iam.addons.federation.web.HtmlEditor.edit(field);
		return true;
	}

}
