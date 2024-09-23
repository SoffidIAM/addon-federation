package es.caib.seycon.idp.shibext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.Collection;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.joda.time.DateTime;
import org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.service.ServerService;
import com.soffid.iam.utils.Security;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class TenantMetadataProvider extends AbstractReloadingMetadataProvider {
    final static String METADATA_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata"; //$NON-NLS-1$

    public String tenant;
	private Document doc;
	private DocumentBuilder dBuilder;
	private FederationService federationService;
	
	public TenantMetadataProvider (String tenant) {
		this.tenant = tenant;
	}
	
	@Override
	protected String getMetadataIdentifier() {
		return tenant;
	}

	@Override
	protected byte[] fetchMetadata() throws MetadataProviderException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		Security.nestedLogin(tenant, "anonymous", Security.ALL_PERMISSIONS);
        try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			dBuilder = dbFactory.newDocumentBuilder();
			doc = dBuilder.newDocument();
			
			System.out.println("////////////////////");
			System.out.println("// "+tenant+ "//");
			System.out.println("////////////////////");
			Element element = doc.createElementNS(METADATA_NAMESPACE, "EntitiesDescriptor");
			doc.appendChild(element);
			element.setAttribute("Name", "All Entities at "+tenant);
			if (tenant != null && ! tenant.isEmpty()) {
				federationService = new RemoteServiceLocator().getFederacioService();
				Collection<EntityGroupMember> entityGroups = federationService.findEntityGroupByNom("%");
				
				for (Iterator<EntityGroupMember> it = entityGroups.iterator(); it.hasNext(); )
				{
				    EntityGroupMember eg = (EntityGroupMember) it.next();
				    generateFederationMember(element, eg);
				}
			}
			// write the content into xml file
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");  
			
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(out);

			// Output to console for testing
			// StreamResult result = new StreamResult(System.out);

			transformer.transform(source, result);

			return out.toByteArray();
		} catch (Exception e) {
			throw new MetadataProviderException("Unable to fetch metadata", e);
		} finally {
			Security.nestedLogoff();
		}
	}

    private boolean generateFederationMember(Element element, EntityGroupMember eg) throws SAXException, IOException, InternalErrorException {
        if (eg.getType().equals( "EG") ) { //$NON-NLS-1$
            Element node = doc.createElementNS(METADATA_NAMESPACE, "EntitiesDescriptor"); //$NON-NLS-1$
            node.setAttribute("Name", eg.getDescription()); //$NON-NLS-1$
            
            if (generateChildEntities(eg, node)) {
                element.appendChild(node);
                return true;
            } else
                return false;
        } else {
            FederationMember fm = eg.getFederationMember();
            if (fm != null && fm.getMetadades() != null) {
                String md = fm.getMetadades();
                
                try {
                    Document newDoc = dBuilder.parse(new InputSource(new StringReader(md)));
                    NodeList nl = newDoc.getChildNodes();
                    for (int i = 0; i <  nl.getLength(); i++) {
                        Node n = nl.item(i);
                        Node n2 = doc.adoptNode(n);
                        element.appendChild(n2);
                    }
                    generateChildEntities(eg, element);
                    return true;
                } catch (SAXParseException e) {
                    org.slf4j.Logger log = LoggerFactory.getLogger(getClass());
                    System.err.println ("Error parsing metadata for entity"+fm.getPublicId()); //$NON-NLS-1$
                    log.warn("Error parsing metadata for entity "+fm.getPublicId(), e); //$NON-NLS-1$
                    return generateChildEntities(eg, element);
                }
            } else {
                return generateChildEntities(eg, element);
            }
        } 
    }

    private boolean generateChildEntities(EntityGroupMember eg, Element node) throws SAXException, IOException, InternalErrorException {
        boolean anyChild = false;
        Collection<EntityGroupMember> entities = federationService.findChildren(eg);
        for (Iterator<EntityGroupMember> it2 = entities.iterator(); it2.hasNext(); ) {
            EntityGroupMember egm = (EntityGroupMember) it2.next();
            if (generateFederationMember(node, egm))
                anyChild = true;
        }
        return anyChild;
    }

    long lastCheck =  0;
	public void mayRefresh() throws IOException, InternalErrorException, MetadataProviderException {
		if (Security.getCurrentTenantName() == null || Security.getCurrentTenantName().isEmpty())
			return; 
		
		DateTime lastRefresh = getLastRefresh();
		if (lastRefresh == null || lastCheck + 30000 < System.currentTimeMillis() ) // 3 seconds
		{
			lastCheck = System.currentTimeMillis();

			ServerService server = new RemoteServiceLocator().getServerService();
		    String config = server.getConfig("saml.federation.lastchange");
		    long lastUpdate = 0;
		    try {
		    	lastUpdate = Long.decode(config);
		    } catch (Exception e) {}
	        if (lastRefresh == null || lastUpdate > lastRefresh.toDate().getTime() - 5000) // 5 seconds clock skew
	        	refresh();
		}
	}
}
