package com.soffid.iam.addons.federation.api;

import java.util.Date;

import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class FacialVerification {
	boolean success;
	float similarity;
}
