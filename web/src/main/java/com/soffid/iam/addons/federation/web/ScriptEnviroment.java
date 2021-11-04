package com.soffid.iam.addons.federation.web;

import javax.ejb.CreateException;
import javax.naming.NamingException;

import org.zkoss.zk.au.out.AuScript;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Executions;

import es.caib.seycon.ng.EJBLocator;
import es.caib.seycon.ng.comu.TipusDada;
import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.exception.InternalErrorException;

public class ScriptEnviroment {
	public String getSystemVars (Component c) throws InternalErrorException, NamingException, CreateException
	{
		defineUserAttributes(c);

		StringBuffer sb = new StringBuffer();
		sb.append("{\"serverService\":\"es.caib.seycon.ng.sync.servei.ServerService\","
				+ "\"remoteServiceLocator\":\"es.caib.seycon.ng.remote.RemoteServiceLocator\","
				+ "\"serviceLocatorV1\":\"es.caib.seycon.ng.ServiceLocator\","
				+ "\"serviceProvider\":\"java.lang.String\","
				+ "\"serviceProviderGroup\":\"java.lang.String\","
				+ "\"serviceLocator\":\"com.soffid.iam.ServiceLocator\","
				+ "\"dispatcherService\":\"es.caib.seycon.ng.sync.engine.extobj.BSHAgentbject\"");

			sb.append(", \"accountId\" : \"java.lang.Long\"")
				.append(", \"accountName\" : \"java.lang.String\"")
				.append(", \"passwordPolicy\" : \"java.lang.String\"")
				.append(", \"accountDescription\" : \"java.lang.String\"")
				.append(", \"accountDisabled\" : \"java.lang.String\"")
				.append(", \"active\" : \"java.lang.Boolean\"")
				.append(", \"type\" : \"java.lang.String\"")
				.append(", \"lastLogin\" : \"java.util.Calendar\"")
				.append(", \"lastUpdate\" : \"java.util.Calendar\"")
				.append(", \"lastPasswordUpdate\" : \"java.util.Calendar\"")
				.append(", \"passwordExpiration\" : \"java.util.Calendar\"")
				.append(", \"attributes\" : \"userAttributes\"")
				.append(", \"grantedRoles\" : \"list<grantObject>\"")
				.append(", \"allGrantedRoles\" : \"list<grantObject>\"")
				.append(", \"granted\" : \"list<grantObject>\"")
				.append(", \"allGranted\" : \"list<grantObject>\"");
			sb.append(", \"accountId\" : \"java.lang.Long\"")
			.append(", \"accountName\" : \"java.lang.String\"")
			.append(", \"system\" : \"java.lang.String\"")
			.append(", \"accountDescription\" : \"java.lang.String\"")
			.append(", \"accountDisabled\" : \"java.lang.String\"")
			.append(", \"active\" : \"java.lang.Boolean\"")
			.append(", \"mailAlias\" : \"java.lang.String\"")
			.append(", \"userName\" : \"java.lang.String\"")
			.append(", \"primaryGroup\" : \"java.lang.String\"")
			.append(", \"comments\" : \"java.lang.String\"")
			.append(", \"createdOn\" : \"java.util.Calendar\"")
			.append(", \"modifiedOn\" : \"java.util.Calendar\"")
			.append(", \"mailDomain\" : \"java.lang.String\"")
			.append(", \"fullName\" : \"java.lang.String\"")
			.append(", \"id\" : \"java.lang.Long\"")
			.append(", \"multiSession\" : \"java.lang.Boolean\"")
			.append(", \"firstName\" : \"java.lang.String\"")
			.append(", \"shortName\" : \"java.lang.String\"")
			.append(", \"lastName\" : \"java.lang.String\"")
			.append(", \"lastName2\" : \"java.lang.String\"")
			.append(", \"mailServer\" : \"java.lang.String\"")
			.append(", \"homeServer\" : \"java.lang.String\"")
			.append(", \"profileServer\" : \"java.lang.String\"")
			.append(", \"phone\" : \"java.lang.String\"")
			.append(", \"userType\" : \"java.lang.String\"")
			.append(", \"createdBy\" : \"java.lang.String\"")
			.append(", \"modifiedBy\" : \"java.lang.String\"")
			.append(", \"primaryGroupObject\" : \"groupObject\"")
			.append(", \"secondaryGroups\" : \"list<groupObject>\"")
			.append(", \"accountAttributes\" : \"accountAttributes\"")
			.append(", \"userAttributes\" : \"userAttributes\"")
			.append(", \"attributes\" : \"userAttributes\"") 
			.append(", \"grantedRoles\" : \"list<grantObject>\"")
			.append(", \"allGrantedRoles\" : \"list<grantObject>\"")
			.append(", \"granted\" : \"list<grantObject>\"")
			.append(", \"allGranted\" : \"list<grantObject>\"");

		sb.append("}");
		return sb.toString();
	}


	private void defineUserAttributes(Component c) throws InternalErrorException, NamingException, CreateException
	{
		StringBuffer sb = new StringBuffer();
		
		for (TipusDada td: EJBLocator.getDadesAddicionalsService().getTipusDades())
		{
			if ( sb.length() > 0)
				sb.append(",");
			sb.append("'{\"").append(td.getCodi()).append("\"}':\"");
			TypeEnumeration t = td.getType();
			if (t == TypeEnumeration.BINARY_TYPE || t == TypeEnumeration.PHOTO_TYPE)
				sb.append("byte");
			else if (t == TypeEnumeration.DATE_TYPE)
				sb.append("java.util.Calendar");
			else
				sb.append("java.lang.String");
			sb.append("\"");
		}
		Executions.getCurrent().addAuResponse(null,
				new AuScript(null, "CodeMirrorJavaTypes[\"userAttributes\"]={"+sb.toString()+"};")); 
		
	}


	public String getAdaptiveVars (Component c) throws InternalErrorException, NamingException, CreateException
	{
		StringBuffer sb = new StringBuffer();
		sb.append("{\"serverService\":\"es.caib.seycon.ng.sync.servei.ServerService\","
				+ "\"remoteServiceLocator\":\"es.caib.seycon.ng.remote.RemoteServiceLocator\","
				+ "\"serviceLocatorV1\":\"es.caib.seycon.ng.ServiceLocator\","
				+ "\"serviceProvider\":\"java.lang.String\","
				+ "\"serviceProviderGroup\":\"java.lang.String\","
				+ "\"serviceLocator\":\"com.soffid.iam.ServiceLocator\","
				+ "\"dispatcherService\":\"es.caib.seycon.ng.sync.engine.extobj.BSHAgentbject\"");

		sb.append(", \"dayOfWeek\" : \"java.lang.Integer\"")
			.append(", \"daysSinceLastLogon\" : \"java.lang.Integer\"")
			.append(", \"daysSinceLastLogonFromSameHost\" : \"java.lang.Integer\"")
			.append(", \"failuresForSameIp\" : \"java.lang.Integer\"")
			.append(", \"secondsSinceLastFail\" : \"java.lang.Integer\"")
			.append(", \"failuresForSameUser\" : \"java.lang.Integer\"")
			.append(", \"failuresRatio\" : \"java.lang.Double\"")
			.append(", \"hour\" : \"java.lang.Integer\"")
			.append(", \"identityProvider\" : \"java.lang.String\"")
			.append(", \"serviceProvider\" : \"java.lang.String\"")
			.append(", \"ipAddress\" : \"java.lang.String\"")
			.append(", \"minute\" : \"java.lang.Integer\"")
			.append(", \"newDevice\" : \"java.lang.Boolean\"")
			.append(", \"sameCountry\" : \"java.lang.Boolean\"")
			.append(", \"serviceProvider\" : \"java.lang.String\"")
			.append(", \"sourceCounty\" : \"java.lang.String\"")
			.append(", \"user\" : \"com.soffid.iam.api.User\"");

			sb.append("}");
		return sb.toString();
	}

}

