package com.soffid.iam.addons.federation.web;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.zkoss.util.resource.Labels;
import org.zkoss.zk.au.out.AuScript;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.Page;
import org.zkoss.zk.ui.UiException;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.component.FrameHandler;
import com.soffid.iam.web.popup.CsvParser;
import com.soffid.iam.web.popup.ImportCsvHandler;

import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.datasource.CommitException;
import es.caib.zkib.datasource.DataSource;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.jxpath.JXPathContext;
import es.caib.zkib.jxpath.Pointer;
import es.caib.zkib.zkiblaf.Missatgebox;

public class AttributeHandler extends FrameHandler {
	private boolean isMaster;
	private boolean canCreateParameter;
	private boolean canUpdateParameter;
	private boolean canDeleteParameter;
	private boolean canQueryParameter;

	public AttributeHandler() throws InternalErrorException {
		
	}

	@Override
	public void setPage(Page p) {
		super.setPage(p);
		getNamespace().setVariable("isMaster", isMaster, true);
		getNamespace().setVariable("canCreateParameter", canCreateParameter, true);
		getNamespace().setVariable("canUpdateParameter", canUpdateParameter, true);
		getNamespace().setVariable("canDeleteParameter", canDeleteParameter, true);
		getNamespace().setVariable("canQueryParameter", canQueryParameter, true);
	}
		

	public void onChangeDades() {
	}
	
	public void importCsv () throws IOException, CommitException {
		getModel().commit();
		
		String[][] data = { 
				{"name", Labels.getLabel("federa_atribut.zul.Name-2")},
				{"shortName", Labels.getLabel("federa_atribut.zul.ShortName-2")},
				{"oid", Labels.getLabel("federa_atribut.zul.Oid")},
				{"openidName", Labels.getLabel("federa_atribut.zul.openidName")},
				{"value", Labels.getLabel("federacio.zul.value")}
		};
		String title = Labels.getLabel("tenant.zul.import");
		ImportCsvHandler.startWizard(title, data, this, 
				parser -> importCsv(parser));
	}

	private void importCsv(CsvParser parser) {
		Map<String,String> m = null;
		int updates = 0;
		int inserts = 0;
		int unchanged = 0;
		int removed = 0;
		try {
			FederationService configSvc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			for ( Iterator<Map<String, String>> iterator = parser.iterator(); iterator.hasNext(); )
			{
				m = iterator.next();
				String name = m.get("name");
				String network = m.get("networkName");
				String description = m.get("description");
				String value = m.get("value");
				if (network != null && network.isEmpty()) network = null;

				if (name != null && !name.trim().isEmpty() && m.containsKey("value"))
				{
					Collection<Attribute> l = configSvc.findAtributs(name, "%", "%");
					Attribute cfg  = l == null || l .isEmpty()? null: l.iterator().next();
					if (cfg != null)
					{
						if (value == null) {
							configSvc.delete(cfg);
							removed ++;
						}
						else if (cfg.getValue() != null && cfg.getValue().equals(value))
						{
							unchanged ++;
						} else {
							if (m.containsKey("value"))
								cfg.setValue(m.get("value"));
							if (m.containsKey("oid"))
								cfg.setOid(m.get("oid"));
							if (m.containsKey("shortName"))
								cfg.setShortName(m.get("shartName"));
							if (m.containsKey("openidName"))
								cfg.setOpenidName(m.get("openidName"));
							configSvc.update(cfg);
							updates ++;
						}
					} else if (value != null) {
						inserts ++;
						cfg = new Attribute();
						m.put("name", m.get("name"));
						if (m.containsKey("value"))
							cfg.setValue(m.get("value"));
						if (m.containsKey("oid"))
							cfg.setOid(m.get("oid"));
						if (m.containsKey("shortName"))
							cfg.setShortName(m.get("shartName"));
						if (m.containsKey("openidName"))
							cfg.setOpenidName(m.get("openidName"));
						configSvc.create(cfg);
					}
				}
			}
		} catch (UiException e) {
			throw e;
		} catch (Exception e) {
			if (m == null)
				throw new UiException(e);
			else
				throw new UiException("Error loading parameter "+m.get("name"), e);
		}
		
		getModel().refresh();
		Missatgebox.avis(Labels.getLabel("parametres.zul.import", new Object[] { updates, inserts, removed, unchanged }));
	}

	@Override
	public void afterCompose() {
		super.afterCompose();
		CustomField3 cf = (CustomField3) getFellow("script");

		defineUserAttributes(cf);

		StringBuffer sb = new StringBuffer();
		sb.append("{\"serverService\":\"es.caib.seycon.ng.sync.servei.ServerService\","
				+ "\"remoteServiceLocator\":\"es.caib.seycon.ng.remote.RemoteServiceLocator\","
				+ "\"serviceLocatorV1\":\"es.caib.seycon.ng.ServiceLocator\","
				+ "\"serviceLocator\":\"com.soffid.iam.ServiceLocator\"");

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
			.append(", \"allGranted\" : \"list<grantObject>\"")
			.append("}");
		
		cf.setJavascript(sb.toString());
	}

	private void defineUserAttributes(Component cf) 
	{
		StringBuffer sb = new StringBuffer();
		
		try {
			for (DataType td: EJBLocator.getAdditionalDataService().getDataTypes())
			{
				if ( sb.length() > 0)
					sb.append(",");
				sb.append("'{\"").append(td.getCode()).append("\"}':\"");
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
		} catch (InternalErrorException | NamingException | CreateException e) {
		}
		
	}

}
