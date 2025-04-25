package com.soffid.iam.addons.federation.api;

import java.util.Date;

import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class DocumentVerification {
	boolean success;
	int code;
	String status;
	String reason;
	String gender;
	String idNumber;
	String firstName;
	String lastName;
	String documentType;
	String documentNumber;
	String documentCountry;
	Date documentValidUntil;
	Date birthDate;
}
