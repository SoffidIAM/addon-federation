package com.soffid.iam.addons.federation.service;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;

import javax.imageio.ImageIO;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONWriter;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.soffid.iam.addons.federation.api.DocumentVerification;
import com.soffid.iam.addons.federation.api.FacialVerification;
import com.soffid.iam.addons.federation.api.LivenessVerification;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity;
import com.soffid.iam.addons.federation.service.impl.FacephiInvocation;

import es.caib.seycon.ng.exception.InternalErrorException;

public class IdentityVerificationServiceImpl extends IdentityVerificationServiceBase {
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected byte[] handleGeneratePngQr(String url) throws Exception {
		QRCodeWriter barcodeWriter = new QRCodeWriter();
	    BitMatrix bitMatrix = 
	    	      barcodeWriter.encode(url, BarcodeFormat.QR_CODE, 200, 200);

   	    BufferedImage img = MatrixToImageWriter.toBufferedImage(bitMatrix);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ImageIO.write(img, "png", out);
		return out.toByteArray();
	}

	@Override
	protected String handleStartDocumentVerification(String identityProvider,
			String country, String type, String mimeType, byte[] front,
			byte[] back) throws Exception {
		String key = getApiKey(identityProvider);
		
		if (key == null)
			throw new InternalErrorException("Cannot find API key for identity provider "+identityProvider);

		FacephiInvocation i = new FacephiInvocation(key);
		i.invoke("https://api.identity-platform.io/verify/documentValidation/v2/start",
				(w) -> {
					JSONWriter writer = new JSONWriter(w);
					writer.object();
					writer.key("country");
					writer.value(country);
					
					writer.key("idType");
					writer.value(type);
					
					writer.key("documentRawImageMimeType");
					writer.value(mimeType);
					
					writer.key("documentFrontRawImage");
					writer.value(Base64.getEncoder().encodeToString(front));
					if (back != null) {
						writer.key("documentBackRawImage");
						writer.value(Base64.getEncoder().encodeToString(back));
					}
					writer.endObject();
					w.close();
					
				});
		int status = i.getStatus();
		if (status == 200) {
			return i.getResult().toString();
		}
		else
		{
			log.warn ("Error starting document verification: Error HTTP/"+status+"\n"+i.getError());
			throw new InternalErrorException("Error HTTP/"+status);
		}
	}

	protected String getApiKey(String identityProvider) {
		String key = null;
		for (FederationMemberEntity idp: getFederationMemberEntityDao().findFMByPublicId(identityProvider)) {
			if (idp instanceof VirtualIdentityProviderEntity) {
				VirtualIdentityProviderEntity vip = (VirtualIdentityProviderEntity) idp;
				if (Boolean.TRUE.equals(vip.getAllowFacephiRegister()) &&
						vip.getFacephiApiKey() != null &&
						!vip.getFacephiApiKey().isBlank()) {
					key = vip.getFacephiApiKey();
					break;
				}
			}
		}
		return key;
	}

	@Override
	protected DocumentVerification handleGetDocumentVerification(String idp,
			String verificationId) throws Exception {
		JSONObject o = new JSONObject(verificationId);
		String key = getApiKey(idp);

		FacephiInvocation i = new FacephiInvocation(key);
		i.invoke("https://api.identity-platform.io/verify/documentValidation/v2/status",
				(w) -> {
					JSONWriter writer = new JSONWriter(w);
					writer.object();
					writer.key("scanReference");
					writer.value(o.getString("scanReference"));
					
					writer.key("type");
					writer.value(o.getString("type"));
					
					writer.endObject();
				});
		
		int status = i.getStatus();
		if (status == 404) {
			DocumentVerification df = new DocumentVerification();
			df.setCode(404);
			df.setStatus("NotFound");
			return df;
		}
		else if (status == 200) {
			JSONObject response = i.getResult();
			if ("DONE".equals(response.get("status"))) {
				return parseDocumentVerification(o, key);
			}
			else {
				DocumentVerification df = new DocumentVerification();
				df.setStatus(response.getString("status"));
				return df;
			}
		}
		else
		{
			log.warn ("Error starting document verification: Error HTTP/"+status+"\n"+i.getError());
			throw new InternalErrorException("Error HTTP/"+status);
		}
	}

	private DocumentVerification parseDocumentVerification(JSONObject o, String key) throws MalformedURLException, IOException, InternalErrorException, JSONException, ParseException {
		FacephiInvocation i = new FacephiInvocation(key);
		i.invoke ("https://api.identity-platform.io/verify/documentValidation/v2/data",
				(w) -> {
					JSONWriter writer = new JSONWriter(w);
					writer.object();
					writer.key("scanReference");
					writer.value(o.getString("scanReference"));
					
					writer.key("type");
					writer.value(o.getString("type"));
					
					writer.endObject();
					w.close();
				});
		
		int status = i.getStatus();
		if (status == 200) {
			JSONObject response = i.getResult();
			DocumentVerification df = new DocumentVerification();
			JSONObject verification = response.getJSONObject("verification");
			df.setStatus(verification.getString("status"));
			df.setCode(verification.getInt("code"));
			final JSONObject document = verification.getJSONObject("document");
			df.setDocumentCountry(document.optString("country", null));
			df.setDocumentNumber(document.optString("number", null));
			df.setDocumentType(document.optString("type", null));
			if (document.optString("validUntil", null) != null)
				df.setDocumentValidUntil(new SimpleDateFormat("yyyy-MM-dd").parse(
						document.getString("validUntil")));
			final JSONObject person = verification.getJSONObject("person");
			df.setFirstName(person.optString("firstName", null));
 			df.setLastName(person.optString("lastName", null));
 			if (person.optString("dateOfBirth", null) != null)
				df.setBirthDate(new SimpleDateFormat("yyyy-MM-dd").parse(
						person.getString("dateOfBirth")));
			df.setReason(verification.optString("reason", null));
			df.setSuccess("approved".equals(verification.get("status")));
			df.setFinished(true);
			return df;
		}
		else
		{
			log.warn ("Error starting document verification: Error HTTP/"+status+"\n"+i.getError());
			throw new InternalErrorException("Error HTTP/"+status);
		}
	}

	@Override
	protected FacialVerification handleAuthenticateFacial(String identityProvider,
			byte[] face, byte[] template) throws Exception {
		String key = getApiKey(identityProvider);
		
		{
			FileOutputStream f1 = new FileOutputStream("/tmp/image1");
			OutputStreamWriter ow = new OutputStreamWriter(f1);
			JSONWriter writer = new JSONWriter(ow);
			writer.object();
			writer.key("token1");
			writer.value(Base64.getEncoder().encodeToString(face));
			
			writer.key("token2");
			writer.value(Base64.getEncoder().encodeToString(template));
			
			writer.key("method");
			writer.value(3); // IDCARD Face
			writer.endObject();
			ow.close();
			f1.close();
		}
		
		if (key == null)
			throw new InternalErrorException("Cannot find API key for identity provider "+identityProvider);

		FacephiInvocation i = new FacephiInvocation(key);
		i.invoke("https://api.identity-platform.io/services/authenticateFacial",
				(w) -> {
					JSONWriter writer = new JSONWriter(w);
					writer.object();
					writer.key("token1");
					writer.value(Base64.getEncoder().encodeToString(face));
					
					writer.key("token2");
					writer.value(Base64.getEncoder().encodeToString(template));
					
					writer.key("method");
					writer.value(3); // IDCARD Face
					writer.endObject();
					w.close();
					
				});
		int status = i.getStatus();
		if (status == 200) {
			JSONObject result = i.getResult();
			FacialVerification v = new FacialVerification();
			v.setSuccess("Positive".equals(result.optString("serviceResultLog")));
			v.setSimilarity(result.optFloat("serviceFacialSimilarityResult", 0.0F));
			return v;
		}
		else
		{
			log.warn ("Error starting document verification: Error HTTP/"+status+"\n"+i.getError());
			throw new InternalErrorException("Error HTTP/"+status);
		}
	}

	@Override
	protected LivenessVerification handlePassiveLiveness(String identityProvider, byte[] image1) throws Exception {
		String key = getApiKey(identityProvider);
		
		if (key == null)
			throw new InternalErrorException("Cannot find API key for identity provider "+identityProvider);

		FacephiInvocation i = new FacephiInvocation(key);
		i.invoke("https://api.identity-platform.io/services/evaluatePassiveLivenessToken",
				(w) -> {
					JSONWriter writer = new JSONWriter(w);
					writer.object();
					writer.key("imageBuffer");
					writer.value(Base64.getEncoder().encodeToString(image1));
					writer.endObject();
					w.close();
					
				});
		int status = i.getStatus();
		if (status == 200) {
			JSONObject result = i.getResult();
			LivenessVerification v = new LivenessVerification();
			v.setSuccess("Live".equals(result.optString("serviceResultLog")));
			return v;
		}
		else
		{
			log.warn ("Error starting document verification: Error HTTP/"+status+"\n"+i.getError());
			throw new InternalErrorException("Error HTTP/"+status);
		}
	}
}
