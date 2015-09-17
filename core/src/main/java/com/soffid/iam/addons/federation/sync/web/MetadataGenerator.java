package com.soffid.iam.addons.federation.sync.web;

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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.sync.ServerServiceLocator;

import es.caib.seycon.ng.exception.InternalErrorException;

public class MetadataGenerator extends HttpServlet {
    @Override
    public void init() throws ServletException {
        super.init();
        federacioService = (FederacioService) ServerServiceLocator.instance().
        		getService(FederacioService.SERVICE_NAME);
    }

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    final static String AFP_NAMESPACE = "urn:mace:shibboleth:2.0:afp";
    final static String XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance";
    final static String BASIC_NAMESPACE = "urn:mace:shibboleth:2.0:afp:mf:basic";
    final static String RP_NAMESPACE = "urn:mace:shibboleth:2.0:relying-party";
    final static String SECURITY_NAMESPACE = "urn:mace:shibboleth:2.0:security";
    final static String METADATA_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata";
    FederacioService federacioService;
    Document doc;
    private DocumentBuilder dBuilder;

    public MetadataGenerator() {
        super();
    }
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        resp.setContentType("text/xml");
        try {
            generate (resp.getOutputStream());
        } catch (Exception e) {
            throw new ServletException(e);
        }
        
    }

    void generate (OutputStream out) throws SAXException, IOException, ParserConfigurationException, TransformerException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        dBuilder = dbFactory.newDocumentBuilder();
        doc = dBuilder.newDocument();
        
        Collection entityGroups = federacioService.findEntityGroupByNom("%");
        Element element = doc.createElementNS(METADATA_NAMESPACE, "EntitiesDescriptor");
        element.setAttribute("Name", "All Entities");
        element.setAttribute("cacheDuration", "PT10M");
        doc.appendChild(element);
        
        for (java.util.Iterator it = entityGroups.iterator(); it.hasNext(); )
        {
            EntityGroupMember eg = (EntityGroupMember) it.next();
            generateFederationMember(element, eg);
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
        
     }


    private boolean generateFederationMember(Element element, EntityGroupMember eg) throws SAXException, IOException, InternalErrorException {
        if (eg.getTipus().equals( "EG") ) {
            boolean anyChild = false;
            Element node = doc.createElementNS(METADATA_NAMESPACE, "EntitiesDescriptor");
            node.setAttribute("Name", eg.getDescripcio());
            
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
                    while (nl.getLength()>0) {
                        Node n = nl.item(0);
                        Node n2 = doc.adoptNode(n);
                        element.appendChild(n2);
                    }
                    generateChildEntities(eg, element);
                    return true;
                } catch (SAXParseException e) {
                    Comment comment = doc.createComment(
                            "*** ERROR ***\n"+
                            "Error parsing metadata for member "+fm.getPublicId()+" ("+fm.getId()+"): \n"+
                                    e.toString()+
                                    "\n*** ERROR ***");
                    element.appendChild(comment);
//                    log("Error parsing metadata for entity "+fm.getPublicId(), e);
                    return generateChildEntities(eg, element);
                }
            } else {
                return generateChildEntities(eg, element);
            }
        } 
    }

    private boolean generateChildEntities(EntityGroupMember eg, Element node) throws SAXException, IOException, InternalErrorException {
        boolean anyChild = false;
        Collection entities = federacioService.findChildren(eg);
        for (java.util.Iterator it2 = entities.iterator(); it2.hasNext(); ) {
            EntityGroupMember egm = (EntityGroupMember) it2.next();
            if (generateFederationMember(node, egm))
                anyChild = true;
        }
        return anyChild;
    }
}
