package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.PrintStream;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.config.IdpConfig;

public class MetadataServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/SAML/metadata.xml"; //$NON-NLS-1$

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	try {
	    	resp.setContentType("text/xml");
	    	ServletOutputStream out = resp.getOutputStream();
	    	PrintStream p = new PrintStream(out);
	    	p.println("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
	    			+ "<EntitiesDescriptor Name=\"All Entities\" cacheDuration=\"PT10M\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n");
	    	IdpConfig cfg = IdpConfig.getConfig();
			p.println(cfg.getFederationMember().getMetadades());
	    	for (FederationMember virtual: cfg.getFederationService().findVirtualIdentityProvidersForIdentitiProvider(cfg.getFederationMember().getPublicId()) ) {
	    		p.println(virtual.getMetadades());
	    	}
	    	p.println("</EntitiesDescriptor>");
	    	p.close();
    	} catch (Exception e) {
    		throw new ServletException(e);
    	}
    }


}
