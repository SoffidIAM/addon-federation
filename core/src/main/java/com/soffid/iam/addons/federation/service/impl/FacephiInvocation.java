package com.soffid.iam.addons.federation.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;

import org.json.JSONObject;
import org.json.JSONTokener;
import org.json.JSONWriter;

import es.caib.seycon.ng.exception.InternalErrorException;

public class FacephiInvocation {
	String key;
	JSONObject result;
	String error;
	int status;
	
	public FacephiInvocation(String key) {
		this.key = key;
	}

	public void invoke(String url, JSONObject data) throws IOException {
		invoke (url, (w) -> {
			w.append(data.toString());
		});
	}

	public void invoke(String url, Writer writer) throws IOException {
		result = null;
		error = null;
		HttpsURLConnection conn = 
				(HttpsURLConnection) 
				new URL(url)
				.openConnection();
		conn.setRequestMethod("POST");
		conn.addRequestProperty("x-api-key", key);
		conn.addRequestProperty("Content-Type", "application/json");
		conn.setDoInput(true);
		conn.setDoOutput(true);
		conn.connect();
		OutputStream out = conn.getOutputStream();
		final OutputStreamWriter w = new OutputStreamWriter(out);
		
		writer.write(w);
		w.close();
		
		status = conn.getResponseCode();
		if (status >= 200 && status < 300) {
			JSONObject response = new JSONObject(new JSONTokener(conn.getInputStream()));
			result = response;
		}
		else
		{
			InputStream in = conn.getErrorStream();
			ByteArrayOutputStream err = new ByteArrayOutputStream();
			byte b[]  = new byte[8192];
			for (int read = in.read(b); read >= 0; read = in.read(b)) 
				err.write(b, 0, read);
			error = err.toString(StandardCharsets.UTF_8);
		}
	}
	
	public interface Writer {
		public void write( OutputStreamWriter w) throws IOException;
	}

	public JSONObject getResult() {
		return result;
	}

	public String getError() {
		if (error == null && result != null)
			return result.toString();
		else
			return error;
	}

	public int getStatus() {
		return status;
	}

}
