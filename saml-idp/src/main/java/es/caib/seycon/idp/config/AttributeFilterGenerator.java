package es.caib.seycon.idp.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.soffid.iam.addons.federation.common.*;
import com.soffid.iam.addons.federation.service.FederacioService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class AttributeFilterGenerator {
	Log log = LogFactory.getLog(getClass());
	
    final static String AFP_NAMESPACE = "urn:mace:shibboleth:2.0:afp"; //$NON-NLS-1$
    final static String XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"; //$NON-NLS-1$
    final static String BASIC_NAMESPACE = "urn:mace:shibboleth:2.0:afp:mf:basic"; //$NON-NLS-1$
    FederacioService fs;
    Document doc;
    public AttributeFilterGenerator(FederacioService fs) {
        super();
        this.fs = fs;
    }
    
    void generate (OutputStream out) throws SAXException, IOException, ParserConfigurationException, TransformerException, InternalErrorException {
    	System.out.println ("Generating attribute-filter.xml"); //$NON-NLS-1$
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        InputStream in = AttributeFilterGenerator.class.
                getResourceAsStream("attribute-filter.xml"); //$NON-NLS-1$
        doc = dBuilder.parse(in );
        
        Node n  = doc.getFirstChild();
        NodeList nList = doc.getElementsByTagNameNS(AFP_NAMESPACE,"AttributeFilterPolicyGroup"); //$NON-NLS-1$
        
        if (nList.getLength() != 1) {
            throw new IOException("Unable to get AttributeFilterPolicyGroup on attribute-filter.xml"); //$NON-NLS-1$
        }
        addPolicies (nList.item(0));
        
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
    private void addPolicies(Node root) throws InternalErrorException {
        Collection policies = fs.findPolicies();
        for (Iterator it = policies.iterator(); it.hasNext();) {
            Policy p = (Policy) it.next();
            
            Element node = doc.createElementNS(AFP_NAMESPACE, "AttributeFilterPolicy"); //$NON-NLS-1$
            node.setAttribute("id", p.getName()); //$NON-NLS-1$
            PolicyCondition cond = p.getCondition();
            
            Element conditionNode = doc.createElementNS(AFP_NAMESPACE, "PolicyRequirementRule"); //$NON-NLS-1$
            generateConditionAttributes (cond, conditionNode, false);
            node.appendChild(conditionNode);
            
            for (Iterator it2  = p.getAttributePolicy().iterator(); it2.hasNext(); ) {
                AttributePolicy ap = (AttributePolicy) it2.next();
                if (ap.getAttribute() == null)
                {
                	log.warn("Attribute policy "+p.getName()+" references unknnown attribute");
                }
                else
                {
	                /**
	                 * <afp:AttributeRule attributeID="eduPersonAffiliation">
	                        <afp:PermitValueRule xsi:type="basic:ANY" />
	                    </afp:AttributeRule>
	                 */
	                Element apNode = doc.createElementNS(AFP_NAMESPACE, "AttributeRule"); //$NON-NLS-1$
	                apNode.setAttribute("attributeID", ap.getAttribute().getShortName()); //$NON-NLS-1$
	                AttributePolicyCondition apc = ap.getAttributePolicyCondition();
	                Element apcNode = doc.createElementNS(AFP_NAMESPACE, apc.getAllow() == null || ! apc.getAllow()? "DenyValueRule": "PermitValueRule"); //$NON-NLS-1$ //$NON-NLS-2$
	                generateConditionAttributes(apc, apcNode, false);
	                apNode.appendChild(apcNode);
	                node.appendChild(apNode);
                }
            }
            
            root.appendChild(node);
        }
    }

    private void generateConditionAttributes(PolicyCondition cond, Element node, boolean ignoreCondition) {
        node.setPrefix("afp"); //$NON-NLS-1$
        if (! ignoreCondition && cond.getNegativeCondition() != null && cond.getNegativeCondition()) {
            node.setAttributeNS(XSI_NAMESPACE, "xsi:type", "basic:NOT"); //$NON-NLS-1$ //$NON-NLS-2$
            Element childNode = doc.createElementNS(BASIC_NAMESPACE, "Rule"); //$NON-NLS-1$
            node.appendChild(childNode);
            generateConditionAttributes(cond, childNode, true);
        } else {
            ConditionType type = cond.getType();
            node.setAttributeNS(XSI_NAMESPACE, "xsi:type", type.getValue()); //$NON-NLS-1$
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
            } else if (type.equals (ConditionType.ATTRIBUTE_SCOPE_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
                generateAttributeIdAttribute(cond, node);
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
                generateAttributeIdAttribute(cond, node);
            } else if (type.equals (ConditionType.ATTRIBUTE_SCOPE_REGEX)) {
                generateRegexAttribute(cond, node);
                generateAttributeIdAttribute(cond, node);
            } else if (type.equals (ConditionType.SCRIPT)) {
                Element child = doc.createElementNS(BASIC_NAMESPACE, "Script"); //$NON-NLS-1$
                child.setTextContent(cond.getValue());
                node.appendChild(child);
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
            node.setAttributeNS(AFP_NAMESPACE, "attributeValueRegex", cond.getRegex()); //$NON-NLS-1$
    }

    private void generateAttributeValueAttribute(PolicyCondition cond,
            Element node) {
        if (cond.getValue() != null)
            node.setAttributeNS(AFP_NAMESPACE, "attributeValue", cond.getValue()); //$NON-NLS-1$
    }

    private void generateAttributeNameAttribute(PolicyCondition cond,
            Element node) {
        if (cond.getNameId() != null)
            node.setAttributeNS(AFP_NAMESPACE, "attributeName", cond.getNameId()); //$NON-NLS-1$
    }

    private void generateNameIdAttribute(PolicyCondition cond, Element node) {
        if (cond.getNameId() != null)
            node.setAttributeNS(AFP_NAMESPACE, "nameIdFormat", cond.getNameId()); //$NON-NLS-1$
    }

    private void generateGroupIdAttribute(PolicyCondition cond, Element node) {
        if (cond.getGroupId() != null)
            node.setAttributeNS(AFP_NAMESPACE, "groupID", cond.getGroupId()); //$NON-NLS-1$
    }

    private void generateRegexAttribute(PolicyCondition cond, Element node) {
        if (cond.getRegex() != null)
            node.setAttributeNS(AFP_NAMESPACE, "regex", cond.getRegex()); //$NON-NLS-1$
    }

    private void generateAttributeIdAttribute(PolicyCondition cond, Element node) {
        if (cond.getAttribute() != null)
            node.setAttributeNS(AFP_NAMESPACE, "attributeID", cond.getAttribute().getShortName()); //$NON-NLS-1$
    }

    private void generateValueAttribute(PolicyCondition cond, Element node) {
        if (cond.getValue() != null)
            node.setAttributeNS(AFP_NAMESPACE, "value", cond.getValue()); //$NON-NLS-1$
    }

    private void generateCaseAttribute(PolicyCondition cond, Element node) {
        if (cond.getIgnoreCase() != null)
            node.setAttributeNS(AFP_NAMESPACE, "ignoreCase", cond.getIgnoreCase().toString()); //$NON-NLS-1$
    }

    @SuppressWarnings("rawtypes")
    private void generateChildConditions(PolicyCondition cond, Element node) {
        for (Iterator it = cond.getChildrenCondition().iterator(); it.hasNext();) {
            PolicyCondition child = (PolicyCondition) it.next();
            Element childNode = doc.createElementNS(BASIC_NAMESPACE, "Rule"); //$NON-NLS-1$
            generateConditionAttributes (child, childNode, false);
            node.appendChild(childNode);
        }
    }
}
