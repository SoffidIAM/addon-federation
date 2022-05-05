package com.soffid.iam.addons.federation.model;

import java.util.LinkedList;

import com.soffid.iam.model.RoleEntity;

public class AllowedScopeEntityDaoImpl extends AllowedScopeEntityDaoBase {
	public void toAllowedScope(com.soffid.iam.addons.federation.model.AllowedScopeEntity source, com.soffid.iam.addons.federation.common.AllowedScope target) {
		super.toAllowedScope(source, target);
		target.setRoles(new LinkedList<String>());
		for (AllowedScopeRoleEntity r: source.getRoles()) {
			RoleEntity role = getRoleEntityDao().load(r.getRoleId());
			if (role != null)
				target.getRoles().add(role.getName()+"@"+role.getSystem().getName());
		}
	}

}
