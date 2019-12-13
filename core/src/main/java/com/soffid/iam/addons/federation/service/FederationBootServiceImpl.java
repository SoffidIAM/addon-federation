package com.soffid.iam.addons.federation.service;

import java.security.Security;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.w3c.dom.Element;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.sync.web.MetadataGenerator;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.MetadataScope;
import com.soffid.iam.api.Tenant;
import com.soffid.iam.sync.SoffidApplication;

import es.caib.seycon.ng.exception.InternalErrorException;

public class FederationBootServiceImpl extends FederationBootServiceBase 
	implements ApplicationContextAware
{
	Log log = LogFactory.getLog(getClass());
	private ApplicationContext applicationContext;
 	@Override
	protected void handleSyncServerBoot() throws Exception {
		SoffidApplication.getJetty().
			bindAdministrationServlet("/SAML/metadata.xml", null, MetadataGenerator.class);

		SoffidApplication.getJetty(). 
			publish(getFederacioService(), FederacioService.REMOTE_PATH, "agent");
		SoffidApplication.getJetty(). 
			publish(getUserBehaviorService(), UserBehaviorService.REMOTE_PATH, "agent");
	}

 	private void testAttribute (String name, String shortName, String oid, String openId) throws InternalErrorException
 	{
 		testAttribute(name, shortName, oid, openId, null);
 	}
 	
 	private void testAttribute (String name, String shortName, String oid, String openId, String value) throws InternalErrorException
 	{
		FederacioService fds = getFederacioService();
		Collection<Attribute> atts = fds.findAtributs(name, null, null);
		if (atts.isEmpty())
		{
			log.info("Creating attribute "+name);
			Attribute att = new Attribute();
			att.setName(name);
			att.setOid(oid);
			att.setShortName(shortName);
			att.setOpenidName(openId);
			att.setValue(null);
			fds.create(att);
		}
		else
		{
			log.info("Attribute "+name+" exists");
			Attribute att = atts.iterator().next();
			if (att.getOpenidName() == null && openId != null)
			{
				att.setOpenidName(openId);
				fds.update(att);
			}
			if (att.getValue() == null && value != null)
			{
				att.setValue(value);
				fds.update(att);
			}
		}
 	}
 	
	@Override
	protected void handleConsoleBoot() throws Exception {

		if (Security.getProvider("BC") == null)
			Security.addProvider( new BouncyCastleProvider());

		testAttribute("User ID", "uid", "urn:oid:0.9.2342.19200300.100.1.1", "sub");
		testAttribute("Full name", "Fullname", "urn:oid:2.16.840.1.113730.3.1.241", "full_name");
		testAttribute("Given Name", "GivenName", "urn:oid:2.5.4.42", "given_name");
		testAttribute("Surname", "Surname", "urn:oid:2.5.4.4", "surname");
		testAttribute("Surnames (all)", "Surnames", "urn:oid:1.3.6.1.4.1.22896.3.1.5", "surnames");
		testAttribute("Phone", "TelephoneNumber", "urn:oid:2.5.4.20", "phone");
		testAttribute("Email address", "mail", "urn:oid:0.9.2342.19200300.100.1.3", "email");
		testAttribute("Organizational unit", "OU", "urn:oid:2.5.4.11", "ou");
		testAttribute("User type", "UserType", "urn:oid:1.3.6.1.4.1.22896.3.1.4", "user_type");
		testAttribute("Role & group membership", "memberOf", "urn:oid:1.3.6.1.4.1.5923.1.5.1.1", "meber_of");
		testAttribute("Session ID", "SessionId", "urn:oid:1.3.6.1.4.1.22896.3.1.1", "session_id");
		testAttribute("Session key", "SessionKey", "urn:oid:1.3.6.1.4.1.22896.3.1.2", null);
		testAttribute("Accounts & Passwords", "Secrets", "urn:oid:1.3.6.1.4.1.22896.3.1.6", null);
		
    	for (DataType md: ServiceLocator.instance().getAdditionalDataService().findDataTypes(MetadataScope.USER))
    	{
    		testAttribute(md.getLabel(), "custom:"+md.getCode(), 
    				"urn:oid:1.3.6.1.4.1.22896.3.1."+md.getId(), md.getCode(), "attributes{\""+md.getCode()+"\"}");
        }

		
		DataSource ds = (DataSource) applicationContext.getBean("dataSource"); //$NON-NLS-1$
		final Connection conn = ds.getConnection();
		try {
			String f = conn.getMetaData().getDatabaseProductName().equalsIgnoreCase("PostgreSQL") ? "false" : "0";
			executeSentence(conn, "UPDATE SC_FEDERA SET ALLOW_REGISTER="+f+" WHERE ALLOW_REGISTER IS NULL"); //$NON-NLS-1$
			executeSentence(conn, "UPDATE SC_FEDERA SET ALLOW_RECOVER="+f+" WHERE ALLOW_RECOVER IS NULL"); //$NON-NLS-1$
			executeSentence(conn, "UPDATE SC_FEDERA SET ALLOW_CERTIFICATE="+f+" WHERE ALLOW_CERTIFICATE IS NULL"); //$NON-NLS-1$
			executeSentence(conn, "UPDATE SC_FEDERA SET FED_KERBEROS="+f+" WHERE FED_KERBEROS IS NULL"); //$NON-NLS-1$
			executeSentence(conn, "UPDATE SC_FEDERA SET FED_DISSSL="+f+" WHERE FED_DISSSL IS NULL"); //$NON-NLS-1$
			executeSentence(conn, "UPDATE SC_FEDERA SET FED_INTERN="+f+" WHERE FED_INTERN IS NULL"); //$NON-NLS-1$
		} finally {
			conn.close ();
		}
		
	}
	
	
	private void executeSentence (Connection conn, String sql, Object ...objects ) throws SQLException
	{
		PreparedStatement stmt = conn.prepareStatement(sql);
		try {
    		parseParameters(stmt, objects);
    		stmt.execute();
		} finally {
			stmt.close ();
		}
	}

	private List<Object[]> executeQuery (Connection conn, String sql, Object ...objects ) throws SQLException
	{
		PreparedStatement stmt = conn.prepareStatement(sql);
		try {
			parseParameters(stmt, objects);
    		ResultSet rset = stmt.executeQuery();
    		try {
        		List<Object[]> result = new LinkedList<Object[]>();
        		int cols = rset.getMetaData().getColumnCount();
        		while (rset.next())
        		{
        			Object [] row = new Object[cols];
        			for (int i = 0; i < cols; i++)
        			{
        				row [i] = rset.getObject(i+1);
        			}
        			result.add(row);
        		}
    			return result;
    		} finally {
    			rset.close ();
    		}
		} finally {
			stmt.close ();
		}
	}

	private void executeQuery (Connection conn, String sql, Object []objects, RowProcessor processor ) throws SQLException, InternalErrorException
	{
		PreparedStatement stmt = conn.prepareStatement(sql);
		try {
			parseParameters(stmt, objects);
    		ResultSet rset = stmt.executeQuery();
    		try {
        		int cols = rset.getMetaData().getColumnCount();
        		while (rset.next())
        		{
        			Object [] row = new Object[cols];
        			for (int i = 0; i < cols; i++)
        			{
        				row [i] = rset.getObject(i+1);
        			}
        			processor.processRow(row);
        		}
    		} finally {
    			rset.close ();
    		}
		} finally {
			stmt.close ();
		}
	}

	protected void parseParameters (PreparedStatement stmt, Object... objects)
					throws SQLException
	{
		int id = 1;
		for (Object p: objects)
		{
			if (p == null)
				stmt.setString(id++, null);
			else if (p instanceof String)
				stmt.setString(id++, (String) p);
			else if (p instanceof Integer)
				stmt.setInt(id++, ((Integer) p).intValue());
			else if (p instanceof Long)
				stmt.setLong(id++, ((Long) p).longValue());
			else if (p instanceof Date)
				stmt.setDate(id++, (Date)p);
			else if (p instanceof java.util.Date)
				stmt.setDate(id++, new Date(((java.util.Date) p).getTime()));
			else 
				stmt.setObject(id++, p);
		}
	}

	@Override
	protected void handleTenantBoot(Tenant arg0) throws Exception {
		testAttribute("User ID", "uid", "urn:oid:0.9.2342.19200300.100.1.1", "sub");
		testAttribute("Full name", "Fullname", "urn:oid:2.16.840.1.113730.3.1.241", "full_name");
		testAttribute("Given Name", "GivenName", "urn:oid:2.5.4.42", "given_name");
		testAttribute("Surname", "Surname", "urn:oid:2.5.4.4", "surname");
		testAttribute("Surnames (all)", "Surnames", "urn:oid:1.3.6.1.4.1.22896.3.1.5", "surnames");
		testAttribute("Phone", "TelephoneNumber", "urn:oid:2.5.4.20", "phone");
		testAttribute("Email address", "Email", "urn:oid:0.9.2342.19200300.100.1.3", "email");
		testAttribute("Organizational unit", "OU", "urn:oid:2.5.4.11", "ou");
		testAttribute("User type", "UserType", "urn:oid:1.3.6.1.4.1.22896.3.1.4", "user_type");
		testAttribute("Role & group membership", "memberOf", "urn:oid:1.3.6.1.4.1.5923.1.5.1.1", "meber_of");
		testAttribute("Session ID", "SessionId", "urn:oid:1.3.6.1.4.1.22896.3.1.1", "session_id");
		testAttribute("Session key", "SessionKey", "urn:oid:1.3.6.1.4.1.22896.3.1.2", null);
		testAttribute("Accounts & Passwords", "Secrets", "urn:oid:1.3.6.1.4.1.22896.3.1.6", null);
	}

	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}
}

interface RowProcessor {
	void processRow (Object [] row) throws SQLException, InternalErrorException;
}
