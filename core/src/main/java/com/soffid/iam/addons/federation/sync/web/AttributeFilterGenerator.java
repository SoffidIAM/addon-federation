package com.soffid.iam.addons.federation.sync.web;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Iterator;

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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.AttributePolicyCondition;
import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.Policy;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.sync.ServerServiceLocator;

import es.caib.seycon.ng.exception.InternalErrorException;

public class AttributeFilterGenerator extends HttpServlet {
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

    @Override
    public void init() throws ServletException {
        super.init();
        fs = (FederationService) ServerServiceLocator.instance().getService(FederationService.SERVICE_NAME);
    }

    @Override
    protected void doHead(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doHead(req, resp);
    }

    final static String AFP_NAMESPACE = "urn:mace:shibboleth:2.0:afp";
    final static String XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance";
    final static String BASIC_NAMESPACE = "urn:mace:shibboleth:2.0:afp:mf:basic";
    
    FederationService fs;
    Document doc;
    
    public AttributeFilterGenerator() {
        super();
    }
    
    synchronized void generate (OutputStream out) throws SAXException, IOException, ParserConfigurationException, TransformerException, InternalErrorException {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        InputStream in = AttributeFilterGenerator.class.
                getResourceAsStream("attribute-filter.xml");
        doc = dBuilder.parse(in );
        
        Node n  = doc.getFirstChild();
        NodeList nList = doc.getElementsByTagNameNS(AFP_NAMESPACE,"AttributeFilterPolicyGroup");
        
        if (nList.getLength() != 1) {
            throw new IOException("Unable to get AttributeFilterPolicyGroup on attribute-filter.xml");
        }
        addPolicies (nList.item(0));
        
        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
//        transformerFactory.setAttribute("indent-number", 4);
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");  
        
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(out);

        // Output to console for testing
        // StreamResult result = new StreamResult(System.out);

        transformer.transform(source, result);
        

     }

    @SuppressWarnings("rawtypes")
    private void addPolicies(Node root) throws InternalErrorException {
        Collection policies = fs.findPolicies();
        for (Iterator it = policies.iterator(); it.hasNext();) {
            Policy p = (Policy) it.next();
            
            Element node = doc.createElementNS(AFP_NAMESPACE, "AttributeFilterPolicy");
            node.setAttribute("id", p.getName());
            PolicyCondition cond = p.getCondition();
            
            Element conditionNode = doc.createElementNS(AFP_NAMESPACE, "PolicyRequirementRule");
            generateConditionAttributes (cond, conditionNode, false);
            node.appendChild(conditionNode);
            
            for (Iterator it2  = p.getAttributePolicy().iterator(); it2.hasNext(); ) {
                AttributePolicy ap = (AttributePolicy) it2.next();
                /**
                 * <afp:AttributeRule attributeID="eduPersonAffiliation">
                        <afp:PermitValueRule xsi:type="basic:ANY" />
                    </afp:AttributeRule>
                 */
                Element apNode = doc.createElementNS(AFP_NAMESPACE, "AttributeRule");
                apNode.setAttribute("attributeID", ap.getAttribute().getShortName());
                AttributePolicyCondition apc = ap.getAttributePolicyCondition();
                Element apcNode = doc.createElementNS(AFP_NAMESPACE, apc.getAllow() == null || ! apc.getAllow()? "DenyValueRule": "PermitValueRule");
                generateConditionAttributes(apc, apcNode, false);
                apNode.appendChild(apcNode);
                node.appendChild(apNode);
            }
            
            root.appendChild(node);
        }
    }

    private void generateConditionAttributes(PolicyCondition cond, Element node, boolean ignoreCondition) {
        node.setPrefix("afp");
        if (! ignoreCondition && cond.getNegativeCondition() != null && cond.getNegativeCondition()) {
            node.setAttribute("xsi:type", "NOT");
            Element childNode = doc.createElementNS(BASIC_NAMESPACE, "Rule");
            node.appendChild(childNode);
            generateConditionAttributes(cond, childNode, true);
        } else {
            ConditionType type = cond.getType();
            node.setAttribute("xsi:type", type.getValue());
            if (type.equals (ConditionType.ANY)) {
                
            } else if (type.equals (ConditionType.AND)) {
                generateChildConditions (cond, node);
            } else if (type.equals (ConditionType.OR)) {
                generateChildConditions (cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_REQUESTER_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_ISSUER_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
            } else if (type.equals (ConditionType.PRINCIPAL_NAME_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
            } else if (type.equals (ConditionType.AUTHENTICATION_METHOD_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_VALUE_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
                generateAttributeIdAttribute(cond, node);
//            } else if (type.equals (ConditionType.ATTRIBUTE_SCOPE_STRING)) {
//                generateValueAttribute(cond, node);
//                generateCaseAttribute(cond, node);
//                generateAttributeIdAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_REQUESTER_REGEX)) {
                generateRegexAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_ISSUER_REGEX)) {
                generateRegexAttribute(cond, node);
            } else if (type.equals (ConditionType.PRINCIPAL_NAME_REGEX)) {
                generateRegexAttribute(cond, node);
            } else if (type.equals (ConditionType.AUTHENTICATION_METHOD_REGEX)) {
                generateRegexAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_VALUE_REGEX)) {
                generateRegexAttribute(cond, node);
//                generateAttributeIdAttribute(cond, node);
//            } else if (type.equals (ConditionType.ATTRIBUTE_SCOPE_REGEX)) {
//                generateRegexAttribute(cond, node);
//                generateAttributeIdAttribute(cond, node);
//            } else if (type.equals (ConditionType.SCRIPT)) {
//                Element child = doc.createElementNS(BASIC_NAMESPACE, "Script");
//                child.setTextContent(cond.getValue());
//                node.appendChild(child);
            } else if (type.equals (ConditionType.ATTRIBUTE_REQUESTER_IN_ENTITY_GROUP)) {
                generateGroupIdAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_ISSUER_IN_ENTITY_GROUP)) {
                generateGroupIdAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_ISSUER_NAME_IDFORMAT_EXACT_MATCH)) {
                generateNameIdAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_REQUESTER_NAME_IDFORMAT_EXACT_MATCH)) {
                generateNameIdAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_EXACT_MATCH)) {
                generateAttributeNameAttribute(cond, node);
                generateAttributeValueAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_EXACT_MATCH)) {
                generateAttributeNameAttribute(cond, node);
                generateAttributeValueAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_REGEX_MATCH)) {
                generateAttributeNameAttribute(cond, node);
                generateAttributeValueRegExAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_REGEX_MATCH)) {
                generateAttributeNameAttribute(cond, node);
                generateAttributeValueRegExAttribute(cond, node);
            }
        }
    }

    private void generateAttributeValueRegExAttribute(PolicyCondition cond,
            Element node) {
        if (cond.getRegex() != null)
            node.setAttribute("attributeValueRegex", cond.getRegex());
    }

    private void generateAttributeValueAttribute(PolicyCondition cond,
            Element node) {
        if (cond.getValue() != null)
            node.setAttribute("attributeValue", cond.getValue());
    }

    private void generateAttributeNameAttribute(PolicyCondition cond,
            Element node) {
        if (cond.getNameId() != null)
            node.setAttribute("attributeName", cond.getNameId());
    }

    private void generateNameIdAttribute(PolicyCondition cond, Element node) {
        if (cond.getNameId() != null)
            node.setAttribute("nameIdFormat", cond.getNameId());
    }

    private void generateGroupIdAttribute(PolicyCondition cond, Element node) {
        if (cond.getGroupId() != null)
            node.setAttribute( "groupID", cond.getGroupId());
    }

    private void generateRegexAttribute(PolicyCondition cond, Element node) {
        if (cond.getRegex() != null)
            node.setAttribute("regex", cond.getRegex());
    }

    private void generateAttributeIdAttribute(PolicyCondition cond, Element node) {
        if (cond.getAttribute() != null)
            node.setAttribute( "attributeID", cond.getAttribute().getShortName());
    }

    private void generateValueAttribute(PolicyCondition cond, Element node) {
        if (cond.getValue() != null)
            node.setAttribute( "value", cond.getValue());
    }

    private void generateCaseAttribute(PolicyCondition cond, Element node) {
        if (cond.getIgnoreCase() != null)
            node.setAttribute( "ignoreCase", cond.getIgnoreCase().toString());
    }

    @SuppressWarnings("rawtypes")
    private void generateChildConditions(PolicyCondition cond, Element node) {
        for (Iterator it = cond.getChildrenCondition().iterator(); it.hasNext();) {
            PolicyCondition child = (PolicyCondition) it.next();
            Element childNode = doc.createElementNS(BASIC_NAMESPACE, "Rule");
            generateConditionAttributes (child, childNode, false);
            node.appendChild(childNode);
        }
    }
}
