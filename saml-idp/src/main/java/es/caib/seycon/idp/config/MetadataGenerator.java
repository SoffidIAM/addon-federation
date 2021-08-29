package es.caib.seycon.idp.config;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import es.caib.seycon.ng.exception.InternalErrorException;
import com.soffid.iam.addons.federation.common.*; 
import com.soffid.iam.addons.federation.service.*;

public class MetadataGenerator {
    final static String AFP_NAMESPACE = "urn:mace:shibboleth:2.0:afp"; //$NON-NLS-1$
    final static String XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"; //$NON-NLS-1$
    final static String BASIC_NAMESPACE = "urn:mace:shibboleth:2.0:afp:mf:basic"; //$NON-NLS-1$
    final static String RP_NAMESPACE = "urn:mace:shibboleth:2.0:relying-party"; //$NON-NLS-1$
    final static String SECURITY_NAMESPACE = "urn:mace:shibboleth:2.0:security"; //$NON-NLS-1$
    final static String METADATA_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata"; //$NON-NLS-1$
    FederationService federacioService;
    FederationMember fm;
    Document doc;
    private DocumentBuilder dBuilder;

    public MetadataGenerator(FederationService fs) {
        super();
        this.federacioService = fs;
    }
    
    void generate (OutputStream out) throws SAXException, IOException, ParserConfigurationException, TransformerException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        dBuilder = dbFactory.newDocumentBuilder();
        doc = dBuilder.newDocument();
        
        Collection<EntityGroupMember> entityGroups = federacioService.findEntityGroupByNom("%"); //$NON-NLS-1$
        Element element = doc.createElementNS(METADATA_NAMESPACE, "EntitiesDescriptor"); //$NON-NLS-1$
        element.setAttribute("Name", "All Entities"); //$NON-NLS-1$ //$NON-NLS-2$
        doc.appendChild(element);
        
        for (Iterator<EntityGroupMember> it = entityGroups.iterator(); it.hasNext(); )
        {
            EntityGroupMember eg = (EntityGroupMember) it.next();
            generateFederationMember(element, eg);
        }
                
        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");   //$NON-NLS-1$
        
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(out);

        // Output to console for testing
        // StreamResult result = new StreamResult(System.out);

        transformer.transform(source, result);
        
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
        Collection<EntityGroupMember> entities = federacioService.findChildren(eg);
        for (Iterator<EntityGroupMember> it2 = entities.iterator(); it2.hasNext(); ) {
            EntityGroupMember egm = (EntityGroupMember) it2.next();
            if (generateFederationMember(node, egm))
                anyChild = true;
        }
        return anyChild;
    }
}
