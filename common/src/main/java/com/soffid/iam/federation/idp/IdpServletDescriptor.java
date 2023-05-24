package com.soffid.iam.federation.idp;

public class IdpServletDescriptor {
	Class className;
	String path;
	public Class getClassName() {
		return className;
	}
	public void setClassName(Class className) {
		this.className = className;
	}
	public String getPath() {
		return path;
	}
	public void setPath(String path) {
		this.path = path;
	}

}
