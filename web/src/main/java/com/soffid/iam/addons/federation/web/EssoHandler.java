package com.soffid.iam.addons.federation.web;

import com.soffid.iam.web.component.FrameHandler;

import es.caib.seycon.ng.exception.InternalErrorException;

public class EssoHandler extends FrameHandler {

	public EssoHandler() throws InternalErrorException {
		super();
	}

	@Override
	public boolean canClose() {
		return true;
	}

}
