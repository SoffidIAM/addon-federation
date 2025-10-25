package com.soffid.iam.addons.federation.model;

import java.util.Collection;
import java.util.LinkedList;

import com.soffid.iam.addons.federation.common.ProgressiveProfile;

public class ProgressiveProfileEntityDaoImpl extends ProgressiveProfileEntityDaoBase {

	@Override
	public void toProgressiveProfile(ProgressiveProfileEntity source, ProgressiveProfile target) {
		super.toProgressiveProfile(source, target);
		LinkedList<String> l = new LinkedList<String>();
		for (ProgressiveProfileFieldEntity fe: source.getFields()) {
			l.add(fe.getField());
		}
		target.setFields(l);
	}

}
