package es.caib.seycon.idp.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.service.AdditionalDataService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class AttributeResolverGenerator {
    final static String RESOLVER_NAMESPACE = "urn:mace:shibboleth:2.0:resolver"; //$NON-NLS-1$
    final static String XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"; //$NON-NLS-1$
    final static String BASIC_NAMESPACE = "urn:mace:shibboleth:2.0:afp:mf:basic"; //$NON-NLS-1$
    AdditionalDataService dataSvc;
    Document doc;
    Set<String> attributes = new HashSet<>();
    
    public AttributeResolverGenerator(AdditionalDataService ds) {
        super();
        this.dataSvc = ds;
    }
    
    void generate (OutputStream out) throws SAXException, IOException, ParserConfigurationException, TransformerException, InternalErrorException {
    	System.out.println ("Generating attribute-resolver.xml"); //$NON-NLS-1$
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        InputStream in = AttributeResolverGenerator.class.
                getResourceAsStream("attribute-resolver.xml"); //$NON-NLS-1$
        doc = dBuilder.parse(in );
        
        Node n  = doc.getFirstChild();
        NodeList nList = doc.getElementsByTagNameNS(RESOLVER_NAMESPACE,"AttributeResolver"); //$NON-NLS-1$
        
        attributes.clear();
        
        if (nList.getLength() != 1) {
            throw new IOException("Unable to get AttributeFilterPolicyGroup on attribute-filter.xml"); //$NON-NLS-1$
        }
//        addCustomAttributes (nList.item(0));
        
        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
//        transformerFactory.setAttribute("indent-number", 4);
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");   //$NON-NLS-1$
        
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(out);

        // Output to console for testing
        // StreamResult result = new StreamResult(System.out);

        transformer.transform(source, result);
        

     }

    @SuppressWarnings("rawtypes")
    private void addCustomAttributes(Node root) throws InternalErrorException, DOMException, IOException {
    	attributes.add("urn:oid:0.9.2342.19200300.100.1.3"); // mail
    	attributes.add("urn:oid:1.3.6.1.4.1.22896.3.1.2"); // mazinger secrets
    	attributes.add("urn:oid:0.9.2342.19200300.100.1.1"); //uid
		attributes.add("urn:oid:1.3.6.1.4.1.22896.3.1.6"); // mazinger secrets 2
		attributes.add("mail");
		attributes.add("uid");
 		attributes.add("mazingerSecrets"); 
 		attributes.add("secrets"); 
    	for ( Attribute att: new RemoteServiceLocator().getFederacioService().findAtributs(null, null, null))
    	{
    		if (! attributes.contains(att.getOid()) && !attributes.contains(att.getShortName())) {
    			attributes.add(att.getOid());
    			attributes.add(att.getShortName());
				
				Element node = doc.createElementNS(RESOLVER_NAMESPACE, "AttributeDefinition"); //$NON-NLS-1$
				node.setAttribute("xsi:type", "ad:Simple"); //$NON-NLS-1$
				node.setAttribute("id", att.getShortName()); //$NON-NLS-1$
				node.setAttribute("sourceAttributeID", att.getShortName().toLowerCase()); //$NON-NLS-1$
				
				Element dependency = doc.createElementNS(RESOLVER_NAMESPACE, "Dependency"); //$NON-NLS-1$
				dependency.setAttribute("ref", "seu"); //$NON-NLS-1$
				node.appendChild(dependency);
				
				Element encoder = doc.createElementNS(RESOLVER_NAMESPACE, "AttributeEncoder"); //$NON-NLS-1$
				encoder.setAttribute("xsi:type", "enc:SAML2String"); //$NON-NLS-1$
				encoder.setAttribute("name", att.getOid()); //$NON-NLS-1$
				encoder.setAttribute("friendlyName", att.getShortName()); //$NON-NLS-1$
				node.appendChild(encoder);
				
				root.appendChild(node);
   			}
        }
    }
}
