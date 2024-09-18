package com.soffid.iam.federation.idp.esso;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.sync.engine.cert.CertificateServer;

import es.caib.seycon.idp.config.IdpConfig;

public class EssoCertServlet extends HttpServlet {
	Log log = LogFactory.getLog(getClass());
	
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
    	doGet(request, response);
    }
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("binary/octet-stream");
        try {
        	FederationMember fm = IdpConfig.getConfig().getFederationMember();
    		StringBuffer sb = new StringBuffer();
    		sb.append("------ CERTS ------\n");
    		for (String s: fm.getSslCertificate().split("[\n\r]+")) {
    			if (s.startsWith("-----END"))
    				sb.append("\n");
    			else if (! s.isBlank() && !s.startsWith("-----BEGIN"))
    				sb.append(s);
    		}
    		byte[] data = sb.toString().getBytes();
            response.setContentLength(data.length);
            response.getOutputStream().write (data);
        } catch (Exception e) {
            log.warn("Error invoking " + request.getRequestURI(), e);
        }
    }
}
