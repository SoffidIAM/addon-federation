package com.soffid.iam.addons.federation.web;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Component;

import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.ConditionTypeEnum;
import com.soffid.iam.addons.federation.common.PolicyCondition;

public class ExpressionHelper {

	public static String getShortDescription(PolicyCondition e) {
		String description;
		if (e == null || e.getType() == null)
			return "";
		
		List literals = ConditionType.literals();
		List names = ConditionType.names();
		int i = literals.indexOf(e.getType().getValue());
		if (i < 0)
			description = e.getType().getValue();
		else
			description = Labels.getLabel("com.soffid.iam.addons.federation.common.ConditionType."+names.get(i));
		if ( Boolean.TRUE.equals(e.getNegativeCondition()))
			description = "NOT "+description;
		if (e.getType() == ConditionType.AND) {
		}
		else if (e.getType() == ConditionType.ANY) {
		}
		else if (e.getType() == ConditionType.OR) {
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_REQUESTER_STRING) {
			description += " '"+e.getValue()+"' "+(Boolean.TRUE.equals(e.getIgnoreCase())? "Ignore case": "");
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_ISSUER_STRING) {
			description += " '"+e.getValue()+"' "+(Boolean.TRUE.equals(e.getIgnoreCase())? "Ignore case": "");
		}
		else if (e.getType() == ConditionType.PRINCIPAL_NAME_STRING) {
			description += " '"+e.getValue()+"' "+(Boolean.TRUE.equals(e.getIgnoreCase())? "Ignore case": "");
		}
		else if (e.getType() == ConditionType.AUTHENTICATION_METHOD_STRING) {
			description += " '"+e.getValue()+"' "+(Boolean.TRUE.equals(e.getIgnoreCase())? "Ignore case": "");
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_VALUE_STRING) {
			if (e.getAttribute() == null)
				description += " '"+e.getValue()+"' "+(Boolean.TRUE.equals(e.getIgnoreCase())? "Ignore case": "");
			else
				description = "Attribute '"+e.getAttribute().getName()+"' value '"+e.getValue()+"' "+(Boolean.TRUE.equals(e.getIgnoreCase())? "Ignore case": "");
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_REQUESTER_REGEX) {
			description += " '"+e.getRegex()+"' ";
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_ISSUER_REGEX) {
			description += " '"+e.getRegex()+"' ";
		}
		else if (e.getType() == ConditionType.PRINCIPAL_NAME_REGEX) {
			description += " '"+e.getRegex()+"' ";
		}
		else if (e.getType() == ConditionType.AUTHENTICATION_METHOD_REGEX) {
			description += " '"+e.getRegex()+"' ";
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_VALUE_REGEX)  {
			if (e.getAttribute() == null)
				description += " '"+e.getRegex()+"' ";
			else
				description = "Attribute '"+e.getAttribute().getName()+"' value '"+e.getRegex()+"' ";
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_REQUESTER_IN_ENTITY_GROUP) {
			description += " '"+e.getGroupId()+"' ";
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_ISSUER_IN_ENTITY_GROUP) {
			description += " '"+e.getGroupId()+"' ";
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_ISSUER_NAME_IDFORMAT_EXACT_MATCH) {
			description += " '"+e.getAttributeNameFormat()+"' ";
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_EXACT_MATCH) {
			description += " '"+e.getNameId()+"' value '"+e.getValue()+"' format "+e.getAttributeNameFormat();
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_EXACT_MATCH) {
			description += " '"+e.getNameId()+"' regex '"+e.getRegex()+"' format "+e.getAttributeNameFormat();
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_EXACT_MATCH) {
			description += " '"+e.getNameId()+"' value '"+e.getValue()+"' format "+e.getAttributeNameFormat();
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_EXACT_MATCH) {
			description += " '"+e.getNameId()+"' regex '"+e.getRegex()+"' format "+e.getAttributeNameFormat();
		}
		else if (e.getType() == ConditionType.ATTRIBUTE_REQUESTER_NAME_IDFORMAT_EXACT_MATCH) {
			description += " '"+e.getAttributeNameFormat()+"' ";
		}

		return description;
	}

	public static int getMinChildren(PolicyCondition e) {
		if (e == null || e.getType() == null)
			return 0;
		
		if (e.getType() == ConditionType.AND) {
			return 2;
		}
		else if (e.getType() == ConditionType.OR) {
			return 2;
		}
		else {
			return 0;
		}
	}

	public static int getMaxChildren(PolicyCondition e) {
		if (e == null || e.getType() == null)
			return 0;
		
		if (e.getType() == ConditionType.AND) {
			return -1;
		}
		else if (e.getType() == ConditionType.OR) {
			return -1;
		}
		else {
			return 0;
		}
	}

	public static String getLongDescription(PolicyCondition condition) {
		String desc = getShortDescription(condition);
		if (condition.getType() == ConditionType.AND || condition.getType() == ConditionType.OR) {
			if (Boolean.TRUE.equals(condition.getNegativeCondition()))
				desc = "NOT (";
			boolean first = true;
			for (PolicyCondition child: condition.getChildrenCondition()) {
				if (first) first = false;
				else desc += condition.getType() == ConditionType.OR? " OR " : " AND ";
				desc = desc + getLongDescription(child);
			}
			if (Boolean.TRUE.equals(condition.getNegativeCondition()))
				desc += ")";
		}
		return desc;
	}
}
