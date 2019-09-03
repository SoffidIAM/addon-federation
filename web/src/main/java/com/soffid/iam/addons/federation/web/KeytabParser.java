package com.soffid.iam.addons.federation.web;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.security.auth.kerberos.KerberosPrincipal;

import sun.security.krb5.PrincipalName;
import sun.security.krb5.internal.ktab.*;

import org.zkoss.util.media.Media;
import org.zkoss.zk.ui.UiException;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.KerberosKeytab;

public class KeytabParser {
	public void parse (Media media, FederationMember federationMember) throws IOException
	{
		File tmpFile = File.createTempFile("test", ".keytab");
		FileOutputStream out = new FileOutputStream(tmpFile);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		if (! media.isBinary())
			throw new UiException("Uplodaded data seems to be text. It should be binary a keytab file");
		if (media.inMemory())
		{
			out.write(media.getByteData());
			bout.write(media.getByteData());
		}
		else
		{
			InputStream in = media.getStreamData();
			for (int read = in.read(); read >= 0; read = in.read())
			{
				out.write(read);
				bout.write(read);
			}
		}
		out.close();
		bout.close();
		
		
		KeyTab kt = KeyTab.getInstance(tmpFile);
		for (KeyTabEntry entry: kt.getEntries())
		{
			PrincipalName principal = entry.getService();
			KerberosKeytab kkt = new KerberosKeytab();
			kkt.setDescription("");
			kkt.setDomain( principal.getRealmAsString() );
			kkt.setPrincipal( principal.getName() );
			kkt.setKeyTab(bout.toByteArray());
			federationMember.getKeytabs().add(kkt);
			break;
		}
	}
}
