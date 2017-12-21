package com.soffid.iam.addons.federation.rest;

public class ResponseError {

	String detail = null;

	public ResponseError(String message) {
		detail = message;
	}

	public String getDetail() {
		return detail;
	}

	public void setDetail(String detail) {
		this.detail = detail;
	}
}
