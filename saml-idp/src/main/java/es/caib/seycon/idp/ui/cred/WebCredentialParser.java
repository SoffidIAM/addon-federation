package es.caib.seycon.idp.ui.cred;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

public class WebCredentialParser {
	private Map clientJSON;
	private Map attestation;
	private byte[] id;
	private byte[] rplId;
	private byte flags;
	private int signCount;
	private String aaguid;
	private byte[] credentialId;
	private Map credentialData;
	private byte[] x;
	private byte[] y;
	private byte[] authData;
	private String publicKey;
	private String tokenSigner;

	public void parse ( String clientJSON, String attestation, byte[] challenge ) throws ParseException, JsonParseException, JsonMappingException, IOException, ValidationException, JWTVerificationException, IllegalArgumentException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException, CertificateException
	{
		if (clientJSON == null || clientJSON.trim().isEmpty())
			throw new ParseException ("Missing clientJSON attribute");
		if (attestation == null || attestation.trim().isEmpty())
			throw new ParseException ("Missing attestation attribute");
		

		byte cjs[] =  Base64.getDecoder().decode(clientJSON);
		ObjectMapper jsonMapper = new ObjectMapper();
		this.clientJSON = jsonMapper.readValue(cjs, Map.class);
		System.out.println(this.clientJSON);
		byte[] clientChallenge = Base64.getUrlDecoder().decode( (String) this.clientJSON.get("challenge"));
		if (! Arrays.equals( clientChallenge, challenge))
			throw new ValidationException("Provided challenge does not match the expected one");
		
		byte[] atb = Base64.getDecoder().decode(attestation);
				
		ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
		this.attestation = cborMapper.readValue(atb, Map.class);
		System.out.println(this.attestation);
		authData = (byte[]) this.attestation.get("authData");

		parseAuthData();
		
		parseResponse();
		
		extractPublicKey();
	}

	public void parseAuthentication ( String clientJSON, String authData, byte[] challenge, String signature,
			boolean validateSignature) throws ParseException, JsonParseException, JsonMappingException, IOException, ValidationException, JWTVerificationException, IllegalArgumentException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeyException, SignatureException
	{
		if (clientJSON == null || clientJSON.trim().isEmpty())
			throw new ParseException ("Missing clientJSON attribute");
		if (authData == null || authData.trim().isEmpty())
			throw new ParseException ("Missing authData attribute");
		

		byte cjs[] =  Base64.getDecoder().decode(clientJSON);
		ObjectMapper jsonMapper = new ObjectMapper();
		this.clientJSON = jsonMapper.readValue(cjs, Map.class);
		byte[] clientChallenge = Base64.getUrlDecoder().decode( (String) this.clientJSON.get("challenge"));
		if (! Arrays.equals( clientChallenge, challenge))
			throw new ValidationException("Provided challenge does not match the expected one");
		System.out.println(this.clientJSON);
		
		this.authData = Base64.getDecoder().decode(authData);
				
		parseAuthData();

		if (validateSignature)
			validateSignature ( cjs, signature);
	}
	
	private void validateSignature(byte [] clientData, String signature) throws InvalidKeySpecException, NoSuchAlgorithmException, ValidationException, SignatureException, InvalidKeyException, UnsupportedEncodingException {
		PublicKey pk = KeyFactory
				.getInstance("EC")
				.generatePublic(new X509EncodedKeySpec(
			    		Base64.getDecoder().decode(publicKey)));
		
		Signature sign = Signature.getInstance("SHA256withECDSA");
		sign.initVerify(pk);
		sign.update(this.authData);
//		byte[] ch = Base64.getUrlDecoder().decode(challenge);
		java.security.MessageDigest d = MessageDigest.getInstance("SHA-256");
		byte ch[] = d.digest(clientData);
		sign.update(ch);
		byte[] signatureBinary = Base64.getDecoder().decode(signature);
		boolean ok = sign.verify(signatureBinary);
		if ( ! ok )
			throw new ValidationException("Signature is not valid");
	}

	private void parseResponse() throws ValidationException, UnsupportedEncodingException, JWTVerificationException, IllegalArgumentException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException, CertificateException {
		String fmt = (String) attestation.get("fmt");
		if ("android-safetynet".equals(fmt))
			parseAndroidSafenetResponse();
		else if ("packed".equals(fmt) || "fido-u2f".equals(fmt))
			parsePackedResponse();
//		else
//			throw new ValidationException("Unsupported attestation format "+fmt);
		
	}

	private void parsePackedResponse() throws UnsupportedEncodingException, JWTVerificationException, IllegalArgumentException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException, CertificateException {
		Map attstmt = (Map) attestation.get("attStmt");

		List<byte[]> certs = (List<byte[]>) attstmt.get("x5c");
		if (certs.size() > 0)
		{
			CertificateFactory cf= CertificateFactory.getInstance("X509");
			X509Certificate x509cert=(X509Certificate)cf.generateCertificate(
					new ByteArrayInputStream(certs.get(0)));
			parseCertName(x509cert);
		}
	}

	public void parseCertName(X509Certificate x509cert) {
		X500Principal principal = x509cert.getSubjectX500Principal();
		tokenSigner = principal.getName();
		try {
			for (Rdn rdn: new LdapName(principal.getName()).getRdns()) {
				if (rdn.getType().equals("CN"))
					tokenSigner = (String) Rdn.unescapeValue( rdn.getValue().toString() );
			};
		} catch (InvalidNameException e) {
		}
	}

	private void parseAndroidSafenetResponse() throws UnsupportedEncodingException, JWTVerificationException, IllegalArgumentException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException, CertificateException {
		Map attstmt = (Map) attestation.get("attStmt");
		byte[] jws = (byte[]) attstmt.get("response");
		String s = new String(jws, "UTF-8");
		
//		for (String ss: s.split("\\."))
//		{
//			System.out.println( new String( Base64.getDecoder().decode(ss), "UTF-8" ));
//		}
		
		DecodedJWT jwt = JWT.decode(s);
		Claim certclaim = jwt.getHeaderClaim("x5c");
		if (certclaim != null)
		{
			String cert = certclaim.asArray(String.class)[0];
			CertificateFactory cf= CertificateFactory.getInstance("X509");
			X509Certificate x509cert=(X509Certificate)cf.generateCertificate(
					new ByteArrayInputStream(
							Base64.getDecoder().decode(cert)
					));
			parseCertName(x509cert);
		}
		 
	    for (String claim: jwt.getClaims().keySet())
		{
			System.out.println(claim+" = "+jwt.getClaim(claim).asString());
		}
	    
	    REVISAR: https://medium.com/webauthnworks/verifying-fido2-packed-attestation-a067a9b2facd

		System.out.println(jwt);
	}

	public void parseAuthData()
			throws ValidationException, IOException, JsonParseException, JsonMappingException {
		ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
		ByteBuffer bb = ByteBuffer.wrap(authData);
		
		rplId  = new byte [32];
		bb.get(rplId);
		this.flags = bb.get();
		if ( (flags & 1) == 0)
			throw new ValidationException ("User has not verified the credential");
		this.signCount = bb.getInt(); 
		if ( (flags & 64) != 0) 
		{
			byte []aaguid = new byte [16];
			bb.get(aaguid);
			this.aaguid = getGuuid(aaguid);
			int length = bb.getShort();
			
			this.credentialId = new byte[length];
			bb.get(credentialId);
			
			int len = bb.limit() - bb.position();

			byte[] credential = new byte [len];
			bb.get(credential);
			
			this.credentialData = cborMapper.readValue(credential, Map.class);
			
			Integer keyType = (Integer) credentialData.get("1");
			// COSE is defined at https://tools.ietf.org/html/rfc8152#page-73
			if ( ! new Integer(2).equals(keyType))
				throw new ValidationException("Only EC key type is accepted");
			Integer algorithm = (Integer) credentialData.get("3");
			// Algorithm list is defined at https://www.iana.org/assignments/cose/cose.xhtml#algorithms
			if ( ! new Integer(-7).equals(algorithm))
				throw new ValidationException("Only ECDSA w/ SHA-256 is accepted");
			
			Integer ecKeyType = (Integer) credentialData.get("-1");
//			if ( ! new Integer(1).equals(ecKeyType))
//				throw new ValidationException("Expecting an ephemeral public key");
			x = (byte[]) credentialData.get("-2");
			y = (byte[]) credentialData.get("-3");
			System.out.println(credentialData);
		}
	}
	
	String getGuuid (byte []b)
	{
		int i = 0;
		return String.format("%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x",
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++],
				b[i++]
				);
	}

	public void setClientJSON(Map clientJSON) {
		this.clientJSON = clientJSON;
	}

	public void setAttestation(Map attestation) {
		this.attestation = attestation;
	}

	public void setId(byte[] id) {
		this.id = id;
	}

	public void setRplId(byte[] rplId) {
		this.rplId = rplId;
	}

	public void setFlags(byte flags) {
		this.flags = flags;
	}

	public void setSignCount(int signCount) {
		this.signCount = signCount;
	}

	public void setAaguid(String aaguid) {
		this.aaguid = aaguid;
	}

	public void setCredentialId(byte[] credentialId) {
		this.credentialId = credentialId;
	}

	public void setCredentialData(Map credentialData) {
		this.credentialData = credentialData;
	}

	public void setX(byte[] x) {
		this.x = x;
	}

	public void setY(byte[] y) {
		this.y = y;
	}
	
	private void extractPublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException 
	{
		KeyFactory kf = KeyFactory.getInstance("EC");
		BigInteger x = new BigInteger(this.x);
		BigInteger y = new BigInteger(this.y);
		ECPoint p = new ECPoint(x, y);
		
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
		parameters.init(new ECGenParameterSpec("secp256r1"));
		ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
		
		PublicKey pk = kf.generatePublic(new ECPublicKeySpec( p, ecParameterSpec ));
		this.publicKey = Base64.getEncoder().encodeToString(pk.getEncoded());
//		return Algorithm.ECDSA256((ECPublicKey) pk, null);

	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
		this.publicKey = publicKey;
	}

	public Map getClientJSON() {
		return clientJSON;
	}

	public Map getAttestation() {
		return attestation;
	}

	public byte[] getId() {
		return id;
	}

	public byte[] getRplId() {
		return rplId;
	}

	public byte getFlags() {
		return flags;
	}

	public int getSignCount() {
		return signCount;
	}

	public String getAaguid() {
		return aaguid;
	}

	public byte[] getCredentialId() {
		return credentialId;
	}

	public Map getCredentialData() {
		return credentialData;
	}

	public byte[] getAuthData() {
		return authData;
	}

	public String getTokenSigner() {
		return tokenSigner;
	}
}
