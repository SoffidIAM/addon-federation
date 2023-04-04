package test;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.soffid.iam.ssl.AlwaysTrustConnectionFactory;

public class ImpersonationTest {
	public static void main (String args[]) throws Exception {
		String server = "https://soffid.bubu.lab:5443/";

		String data = "grant_type=password&"+
			"username=dilbert&"+
			"password=Geheim02.&"+
			"client_id=impersonation";
		
		JSONObject o = new JSONObject(doPost(server+"token", data, null));
		
		String token = o.optString("access_token");
		System.out.println(token);
		
		String url2 = "https://samltest.id/Shibboleth.sso/Login?entityID=test-idp3&target=https%3A%2F%2Fsamltest.id%2Fsaml-test&authnContextClassRef=&NameIDFormat=";
		String data2 = "url="+URLEncoder.encode(url2, "UTF-8");
		
		JSONArray a = new JSONArray(doPost(server+"userinfo/impersonate", data2, token));
		
		System.out.println(a);
	}

	private static JSONTokener doPost(String server, String data, String token) throws MalformedURLException, Exception {
		URL url = new URL(server);
    	HttpURLConnection connection = (HttpURLConnection) AlwaysTrustConnectionFactory.getConnection(url);
    	connection.setRequestMethod("POST"); //$NON-NLS-1$
    	if (token != null)
    		connection.addRequestProperty("Authorization", "Bearer "+token);
    	connection.setDoOutput(true);
    	connection.setDoInput(true);
    	connection.connect();
    	OutputStream out = connection.getOutputStream();
    	out.write(data.getBytes("UTF-8"));
    	out.close();
    	int r = connection.getResponseCode();
    	System.out.println("HTTP/"+r);
    	if (r != 200) {
    		InputStream in = connection.getErrorStream();
    		for (int i = in.read(); i >= 0; i = in.read())
    			System.out.write(i);
    		return null;
    	} else {
	    	InputStream in = connection.getInputStream();
	    	return new JSONTokener(in);
    	}
	}
}
