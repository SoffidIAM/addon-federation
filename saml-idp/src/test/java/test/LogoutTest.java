package test;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.TimeZone;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.SigningUtil;
import org.opensaml.xml.util.Base64;

public class LogoutTest {
	public String buildURLHTTPRedirect(String idUserSession, String publicIdServiceProvider,
			String singleLogoutServiceHttpRedirect, String entityIdIdentityProvider, String endURL) throws Exception 
	{
		//1. Generate the SAMLRequest value
		String samlLogoutRequest = buildSamlLogoutRequest(idUserSession, publicIdServiceProvider, singleLogoutServiceHttpRedirect, entityIdIdentityProvider);
		System.out.println("samlLogoutRequest: " + samlLogoutRequest);
		
		//2. Encode the SAMLRequest value in Base64
		String base64SAMLRequest = deflateBase64Encoded(samlLogoutRequest);
		
		//3. URL-encode the SAMLRequest value
		String encoding = "UTF-8"; 
		String urlEncodedSAMLRequest = URLEncoder.encode(base64SAMLRequest, encoding);
		
		//4. URL-encode the SigAlg value: http://www.w3.org/2000/09/xmldsig#rsa-sha1
		// Sign the samlRequest=value&SigAlg=value
		String sigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"; 
		String sigAlgEncoded = URLEncoder.encode(sigAlg, encoding);
		
		String endURLEncoded = URLEncoder.encode(endURL, encoding);
		
		//5. Feed the algorithm signature (SHA1withRSA) with the SAMLRequest=value&SigAlg=value
		String signValue = "SAMLRequest=" + urlEncodedSAMLRequest + "&RelayState=" + endURLEncoded + "&SigAlg=" + sigAlgEncoded;
		
		System.out.println(signValue);
		
		PrivateKey pk = getKey();
		byte[] signature = SigningUtil.sign(pk, "SHA1withRSA", signValue.getBytes());

		//6. URL-encode the generated signature
		String urlEncodedSignature = URLEncoder.encode(Base64.encodeBytes(signature), encoding);
		
		// Constructs the final URL https://endpoint/?SAMLRequest=value&SigAlg=value&Signature=value
		String paramsURL = "?SAMLRequest=" + urlEncodedSAMLRequest
			+ "&SigAlg=" + sigAlgEncoded
			+ "&RelayState=" + endURLEncoded
			+ "&Signature=" + urlEncodedSignature;
		
		return singleLogoutServiceHttpRedirect + paramsURL;
	}

	private PrivateKey getKey() throws KeyStoreException, NoSuchProviderException, IOException,
			NoSuchAlgorithmException, CertificateException, FileNotFoundException, UnrecoverableKeyException {
		Security.addProvider(new BouncyCastleProvider());
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("src/test/conf/sp.p12"), "1234".toCharArray());
		for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
			String entry = e.nextElement();
			if (ks.isKeyEntry(entry))
				return (PrivateKey) ks.getKey(entry, "1234".toCharArray());
		}
		throw new IOException("Cannot find any key");
	}

	private static String buildSamlLogoutRequest(String idUserSession, String publicIdServiceProvider, 
			String singleLogoutServiceHttpRedirect, String entityIdIdentityProvider) {
		
		final SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
		simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
		return "<saml2p:LogoutRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\""
//			+ "xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\""
			+ " ID=\"_" + System.currentTimeMillis() + "_\""
			+ " Version=\"2.0\""
			+ " IssueInstant=\""+ simpleDateFormat.format(new Date()) +"\""
			+ " Destination=\"" + singleLogoutServiceHttpRedirect + "\">"
			+ "<saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + publicIdServiceProvider + "</saml2:Issuer>"
			+ "<saml2:NameID xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\" NameQualifier=\"" + entityIdIdentityProvider + "\">" + idUserSession + "</saml2:NameID>"
			+ "</saml2p:LogoutRequest>";
	}
	

	public static void main(String args[]) throws Exception {
		String s = new LogoutTest().buildURLHTTPRedirect("admin", "https://localhost", "https://soffid.bubu.lab:5443/profile/SAML2/Redirect/SLO", "test-idp3", "relay-state");
		
		System.out.println(s);

		System.out.println(new URL(s).getContent().toString());
	}

	protected String deflateBase64Encoded(String messageStr) throws MessageEncodingException {
        try {
            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
            deflaterStream.write(messageStr.getBytes());
            deflaterStream.finish();

            return Base64.encodeBytes(bytesOut.toByteArray(), Base64.DONT_BREAK_LINES);
        } catch (IOException e) {
            throw new MessageEncodingException("Unable to DEFLATE and Base64 encode SAML message", e);
        }
    }
}
