package com.soffid.iam.federation.idp;

import java.util.EventListener;

import javax.servlet.ServletContextEvent;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.web.context.ContextLoaderListener;

import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

public class SoffidContextLoaderListener extends ContextLoaderListener {

	@Override
	public void contextInitialized(ServletContextEvent event) {
		super.contextInitialized(event);
		if (! "legacy".equals(System.getProperty("soffid.idp.algorithms"))) {
			BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
			// Asymmetric key algorithms
			config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
			config.registerSignatureAlgorithmURI("DSA", SignatureConstants.ALGO_ID_SIGNATURE_DSA);
			config.registerSignatureAlgorithmURI("EC", SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256);
			
			// HMAC algorithms
			config.registerSignatureAlgorithmURI("AES", SignatureConstants.ALGO_ID_MAC_HMAC_SHA256);
			config.registerSignatureAlgorithmURI("DESede", SignatureConstants.ALGO_ID_MAC_HMAC_SHA256);
			
			// Other signature-related params
			config.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			config.setSignatureHMACOutputLength(null);
			config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		}
	}
}
