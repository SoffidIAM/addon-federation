package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationURL;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.idp.textformatter.TextFormatter;

public class HtmlGenerator {
    public static final String ORGANIZATION_NAME = "seu-organization-name"; //$NON-NLS-1$
    public static final String ORGANIZATION_URL = "seu-organization-url"; //$NON-NLS-1$
    private static final String RESOURCE_BUNDLE = "es/caib/seycon/idp/ui/loginPage"; //$NON-NLS-1$
    private Map<String, String> internalParams;
    private List<Locale> langs;

    private ResourceBundle getResourceBundle ()
    {
    	for (Locale lang: langs)
    	{
    		try {
    			return ResourceBundle.getBundle(RESOURCE_BUNDLE, lang,
    					ResourceBundle.Control.getNoFallbackControl(
            					ResourceBundle.Control.FORMAT_PROPERTIES));
    		} catch (Exception e) {
    			// Ignore
    		}
    	}
		return ResourceBundle.getBundle(RESOURCE_BUNDLE, new Locale("en")); //$NON-NLS-1$
    }
    
    public HtmlGenerator(ServletContext ctx, HttpServletRequest request)
            throws ServletException {
        internalParams = new HashMap<String, String>();
        langs = new LinkedList<Locale>();

        String selectedLang = (String) request.getSession()
                .getAttribute("lang"); //$NON-NLS-1$
        if (selectedLang != null)
            langs.add(new Locale(selectedLang));
        
        

        @SuppressWarnings("rawtypes")
        Enumeration e;
        for (e = request.getLocales(); e.hasMoreElements();) {
        	Locale l = (Locale) e.nextElement();
        	if (selectedLang == null)
        		selectedLang = l.getLanguage();
            langs.add(l);
        }

        if (selectedLang != null)
        	internalParams.put("lang.active."+selectedLang, "active"); //$NON-NLS-1$ //$NON-NLS-2$
        IdpConfig idpConfig;
        try {
            idpConfig = IdpConfig.getConfig();
        } catch (Exception e1) {
            throw new ServletException(e1);
        }
        internalParams.put("config.port", //$NON-NLS-1$
                Integer.toString(idpConfig.getStandardPort()));
        internalParams.put("config.sslport", //$NON-NLS-1$
                Integer.toString(idpConfig.getClientCertPort()));
        internalParams.put("config.hostname", idpConfig.getHostName()); //$NON-NLS-1$

        RelyingPartyConfigurationManager relyingPartyConfigurationManager = HttpServletHelper
                .getRelyingPartyConfigurationManager(ctx);
        HttpSession session = request.getSession();
        String method = (String) session
                .getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM);
        String entityId = (String) session
                .getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);

        EntityDescriptor md = HttpServletHelper.getRelyingPartyMetadata(
                entityId, relyingPartyConfigurationManager);

        String user = (String) session.getAttribute(SessionConstants.SEU_USER);
        if (user == null)
            user = (String) session.getAttribute(SessionConstants.SEU_TEMP_USER);
        if (user != null)
            internalParams.put("user", user); //$NON-NLS-1$

        internalParams.put("authMethod", method); //$NON-NLS-1$
        internalParams.put("login_inicio", entityId); //$NON-NLS-1$
        internalParams.put("entityId", entityId); //$NON-NLS-1$
        ResourceBundle rb = getResourceBundle();
        String header;
        if (md != null) {
            Organization org = md.getOrganization();

            // Organization NAME
            if (org != null) {
                List<OrganizationDisplayName> names = org.getDisplayNames();
                List<LocalizedString> names2 = new LinkedList<LocalizedString>();
                for (OrganizationDisplayName name : names) {
                    names2.add(name.getName());
                }
                String orgName = selectLocalized(names2);
                internalParams.put("organizationName", orgName); //$NON-NLS-1$

                // Organization URL
                List<OrganizationURL> urls = org.getURLs();
                List<LocalizedString> urls2 = new LinkedList<LocalizedString>();
                for (OrganizationURL url : urls) {
                    urls2.add(url.getURL());
                }
                internalParams.put("organizationUrl", selectLocalized(urls2)); //$NON-NLS-1$
                if (orgName == null)
                    header = String.format (rb.getString("login.wellcome2"),  //$NON-NLS-1$
                    		md.getEntityID()) ;
                else
                	header = String.format (rb.getString("login.wellcome"),  //$NON-NLS-1$
                		orgName) ;
            }
            else
            {
                header = String.format (rb.getString("login.wellcome2"),  //$NON-NLS-1$
                		md.getEntityID()) ;
            }
        } else {
            header = String.format (rb.getString("login.wellcome"), (String) session.getAttribute(ORGANIZATION_NAME)) ; //$NON-NLS-1$
            internalParams.put("organizationName", (String) session.getAttribute(ORGANIZATION_NAME)); //$NON-NLS-1$
            internalParams.put("organizationUrl", (String) session.getAttribute(ORGANIZATION_URL)); //$NON-NLS-1$
        }
        internalParams.put("header", header); //$NON-NLS-1$
    }

    private String selectLocalized(List<LocalizedString> names) {
        String value = null;
        int priority = langs.size();
        for (LocalizedString name : names) {
            if (value == null)
                value = name.getLocalString();
            String l = name.getLanguage();
            Locale newLang = new Locale(l);
            int newPriority = 0;
            for (Locale lang : langs) {
                if (newLang.getLanguage().equals(lang.getLanguage())
                        && newPriority < priority) {
                    priority = newPriority;
                    value = name.getLocalString();
                    if (priority == 0)
                        return value;
                }
                newPriority++;
                if (newPriority > priority)
                    break;
            }
        }
        return value == null ? "" : value; //$NON-NLS-1$
    }

    public void addArgument(String key, String value) {
        internalParams.put(key, value);
    }

    public void addArguments(Map<String, String> args) {
        internalParams.putAll(args);
    }

    public void generate(HttpServletResponse resp, String page)
            throws TextFormatException, IOException {
        ResourceBundle rb = getResourceBundle();
        generate(resp, page, rb);
    }

    private void generate(HttpServletResponse resp, String page,
            ResourceBundle rb) throws TextFormatException, IOException {
        resp.addHeader("Cache-Control", "no-cache"); //$NON-NLS-1$ //$NON-NLS-2$
        resp.setContentType("text/html; charset=UTF-8"); //$NON-NLS-1$
        
        InputStream in = getClass().getClassLoader().getParent().getResourceAsStream("es/caib/seycon/idp/ui/"+page);
        if (in == null)
        	in = getClass().getClassLoader().getParent().getResourceAsStream("com/soffid/iam/idp/ui/"+page);
        if (in == null)
        	in = HtmlGenerator.class.getResourceAsStream(page);
        new TextFormatter().formatTemplate(in, resp.getOutputStream(), rb,
                internalParams);
    }

}
