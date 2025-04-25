package es.caib.seycon.idp.ui;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

import javax.imageio.ImageIO;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdpNetworkConfig;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class RegisterFormServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/registerForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    String emptyfy (Object obj)
    {
    	if (obj == null)
    		return "";
    	else
    		return obj.toString();
    }
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
        super.doGet(req, resp);

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        try {
	    	FederationMember ip = amf.getIdentityProvider();
	    	if (ip == null || ! ip.isAllowRegister() || ip.getUserTypeToRegister() == null)
	    		throw new ServletException ("Not authorized to self register");

	    	if (ip.isAllowFacephiRegister()) {
	        	resp.setHeader("Content-Security-Policy", "script-src 'self' 'unsafe-inline' "
	        			+ "'unsafe-eval' "
	        			+ "https://www.google.com/recaptcha/ "
	        			+ "https://www.gstatic.com/recaptcha/ "
	        			+ "https://widget-components.facephi.pro/ "
	        			+ "; worker-src blob:");
	        	
	            HtmlGenerator g = new HtmlGenerator(context, req);
	            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
		        g.addArgument("refreshUrl", URI); //$NON-NLS-1$
	            g.addArgument("registerUrl", RegisterFacephiAction.URI);
	            g.addArgument("loginPage", UserPasswordFormServlet.URI);
	            g.addArgument("facephiKey", ip.getFacephiKey());
	            g.addArgument("facephiId", ip.getFacephiId());

	            String url;
	            String referer = req.getParameter("referer");
	            if (referer != null) {
	            	java.net.URI uri = new java.net.URI(referer);
	            	url = uri.getScheme()+"//"+uri.getHost();
	            	if (uri.getPort() > 0)
	            		url = url + ":"+uri.getPort();
	            	url = url + URI;
	            } else {
	            	url = "https://"+ip.getHostName()+URI;
		            for (IdpNetworkConfig c: ip.getNetworkConfig()) {
		            	int port = c.getPort();
		            	if (c.isProxy())
		            		port = c.getProxyPort();
		            	url = "https://"+ip.getHostName()+":"+port+URI;
		            } 
	            }
	            byte []data = new com.soffid.iam.federation.idp.RemoteServiceLocator()
	            		.getIdentityVerificationService()
	            		.generatePngQr(url);
	            String image = "data:image/png;base64,"+Base64.getEncoder().encodeToString(data);
	            
	            g.addArgument("qr", image);
	            g.generate(resp, "registerFacephi.html"); //$NON-NLS-1$
	    	}
	    	else
	    	{
		    	if (! amf.allowUserPassword())
		            throw new ServletException (Messages.getString("UserPasswordFormServlet.methodNotAllowed")); //$NON-NLS-1$
	
	        	
	        	IdpConfig config = IdpConfig.getConfig();
	        	
	            HtmlGenerator g = new HtmlGenerator(context, req);
	            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
	            Map<String,String> args = (Map<String, String>) req.getAttribute("register");
	            if (args != null) {
		            for (String arg: args.keySet()) {
		            	g.addArgument("previous_"+arg, emptyfy( args.get(arg))); //$NON-NLS-1$ //$NON-NLS-2$
		            	
		            }
	            }
		        g.addArgument("refreshUrl", URI); //$NON-NLS-1$
	            g.addArgument("registerUrl", RegisterAction.URI);
	            g.addArgument("loginPage", UserPasswordFormServlet.URI);
	            
	        	ServerService serverService = new RemoteServiceLocator().getServerService();
	        	LogonService logonService = new RemoteServiceLocator().getLogonService();
	        	String userType = ip.getUserTypeToRegister();
	        	g.addArgument("policy", 
	        			config.getFederationService().getPolicyDescriptionForUserType(userType, IdpConfig.getConfig().getSystem().getName()));
	
	            g.generate(resp, "registerPage.html"); //$NON-NLS-1$
	    	}
        } catch (Exception e) {
            throw new ServletException(e);
		}
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    
}
