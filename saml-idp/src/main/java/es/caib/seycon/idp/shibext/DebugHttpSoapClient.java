package es.caib.seycon.idp.shibext;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.ws.soap.client.SOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.parse.ParserPool;

import edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler;

public class DebugHttpSoapClient extends HttpSOAPClient {
	Log log = LogFactory.getLog(SLOProfileHandler.class);
	
	public DebugHttpSoapClient(HttpClient client, ParserPool parser) {
		super(client, parser);
	}

	@Override
    protected void processSuccessfulResponse(PostMethod httpMethod, SOAPMessageContext messageContext)
            throws SOAPClientException {
    	ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
        	InputStream in = httpMethod.getResponseBodyAsStream();
        	int r;
        	while ( (r = in.read()) >= 0)
        		out.write(r);
            Envelope response = unmarshallResponse(new ByteArrayInputStream(out.toByteArray()));
            messageContext.setInboundMessage(response);
            evaluateSecurityPolicy(messageContext);
        } catch (Exception e) {
        	log.info ("Error parsing response: "+out.toString());
            throw new SOAPClientException("Unable to read response", e);
        }
    }

}
