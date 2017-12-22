package com.soffid.iam.addons.federation.rest;

import java.util.Collection;

public class ResponseList {

	Collection<Object> resources = null;

	public ResponseList(Collection<Object> list) {
		this.resources = list;
	}

	public Collection<Object> getResources() {
		return resources;
	}

	public void setResources(Collection<Object> resources) {
		this.resources = resources;
	}
}