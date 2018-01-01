package es.caib.seycon.idp.config;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemWriter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.Password;
import com.soffid.iam.ssl.SeyconKeyStore;
import com.soffid.iam.utils.Security;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.ng.exception.InternalErrorException;

public class RelyingPartyGenerator {
    final static String AFP_NAMESPACE = "urn:mace:shibboleth:2.0:afp"; //$NON-NLS-1$
    final static String XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"; //$NON-NLS-1$
    final static String BASIC_NAMESPACE = "urn:mace:shibboleth:2.0:afp:mf:basic"; //$NON-NLS-1$
    final static String RP_NAMESPACE = "urn:mace:shibboleth:2.0:relying-party"; //$NON-NLS-1$
    final static String SECURITY_NAMESPACE = "urn:mace:shibboleth:2.0:security"; //$NON-NLS-1$
    final static String METADATA_NAMESPACE = "urn:mace:shibboleth:2.0:metadata"; //$NON-NLS-1$
    FederacioService federacioService;
    FederationMember federationMember;
    EntityGroupMember entityGroupMember;
    Document doc;
    private Node rootNode;
    private Node trustEngineNode;

    public RelyingPartyGenerator(FederacioService fs, EntityGroupMember egm) {
        super();
        this.federacioService = fs;
        this.entityGroupMember = egm;
        this.federationMember = egm.getFederationMember();
    }

    void generate(OutputStream out) throws SAXException, IOException,
            ParserConfigurationException, TransformerException,
            UnrecoverableKeyException, InvalidKeyException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException,
            IllegalStateException, NoSuchProviderException, SignatureException,
            InternalErrorException {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        InputStream in = RelyingPartyGenerator.class
                .getResourceAsStream("base-relying-party.xml"); //$NON-NLS-1$
        doc = dBuilder.parse(in);

        Node n = doc.getFirstChild();
        NodeList nList = doc.getElementsByTagNameNS(RP_NAMESPACE,
                "RelyingPartyGroup"); //$NON-NLS-1$

        if (nList.getLength() != 1) {
            throw new IOException(
                    "Unable to get RelyingPartyGroup on base-relying-party.xml"); //$NON-NLS-1$
        }

        rootNode = nList.item(0);
        trustEngineNode = rootNode.getChildNodes().item(0);

        addProfiles();
        addMetaData();
        addKeys();

        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory
                .newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes"); //$NON-NLS-1$

        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(out);

        // Output to console for testing
        // StreamResult result = new StreamResult(System.out);

        transformer.transform(source, result);

    }

    @SuppressWarnings({ "rawtypes", "unused" })
    private void addMetaData() throws FileNotFoundException, IOException,
            UnrecoverableKeyException, InvalidKeyException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException,
            IllegalStateException, NoSuchProviderException, SignatureException,
            InternalErrorException {
        Element mdNode = doc.createElementNS(METADATA_NAMESPACE,
                "MetadataProvider"); //$NON-NLS-1$
        rootNode.insertBefore(mdNode, trustEngineNode);

        mdNode.setAttribute("xsi:type", "metadata:ChainingMetadataProvider"); //$NON-NLS-1$ //$NON-NLS-2$
        mdNode.setAttribute("id", "ShibbolethMetadata"); //$NON-NLS-1$ //$NON-NLS-2$

        Element spmdNode = doc.createElementNS(METADATA_NAMESPACE,
                "MetadataProvider"); //$NON-NLS-1$
        mdNode.appendChild(spmdNode);
        spmdNode.setAttribute("id", "Global-Metadata"); //$NON-NLS-1$ //$NON-NLS-2$
        spmdNode.setAttribute("xsi:type", //$NON-NLS-1$
                "metadata:ResourceBackedMetadataProvider"); //$NON-NLS-1$

        Element confNode = doc.createElementNS(METADATA_NAMESPACE,
                "MetadataResource"); //$NON-NLS-1$
        spmdNode.appendChild(confNode);
        URL server = ServerLocator.getInstance().getServerUrl("/SAML/metadata.xml?tenant="+URLEncoder.encode(Security.getCurrentTenantName(), "UTF-8")); //$NON-NLS-1$
        confNode.setAttribute("url", server.toString()); //$NON-NLS-1$
        confNode.setAttribute("file", new File (IdpConfig.getConfig().getConfDir(), "metadata.xml").getPath()); //$NON-NLS-1$ //$NON-NLS-2$
        confNode.setAttribute("xsi:type", "resource:FileBackedHttpResource"); //$NON-NLS-1$ //$NON-NLS-2$

    }

    private void addKeys() throws UnrecoverableKeyException,
            InvalidKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IllegalStateException,
            NoSuchProviderException, SignatureException, IOException,
            InternalErrorException {
        addKeys(entityGroupMember);
    }

    @SuppressWarnings("rawtypes")
    private void addKeys(EntityGroupMember egm)
            throws UnrecoverableKeyException, InvalidKeyException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IllegalStateException, NoSuchProviderException, SignatureException,
            IOException, InternalErrorException {
        if (egm.getFederationMember().getPrivateKey() != null) {
            addKeys(egm.getFederationMember());
        }
        for (Iterator it = federacioService.findChildren(egm).iterator(); it
                .hasNext();) {
            EntityGroupMember child = (EntityGroupMember) it.next();
            addKeys(child);
        }

    }

    private void addKeys(FederationMember federationMember) throws IOException,
            UnrecoverableKeyException, InvalidKeyException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException,
            IllegalStateException, NoSuchProviderException, SignatureException,
            InternalErrorException {
        Password p = SeyconKeyStore.getKeyStorePassword();
        IdpConfig c = IdpConfig.getConfig();

        Element node = doc.createElementNS(SECURITY_NAMESPACE, "Credential"); //$NON-NLS-1$
        rootNode.insertBefore(node, trustEngineNode);
        node.setAttribute("id", "cred-" + federationMember.getPublicId()); //$NON-NLS-1$ //$NON-NLS-2$
        node.setAttribute("xsi:type", "security:X509Inline"); //$NON-NLS-1$ //$NON-NLS-2$

        // Private key
        Element privateNode = doc.createElementNS(SECURITY_NAMESPACE,
                "PrivateKey"); //$NON-NLS-1$
        node.appendChild(privateNode);
        privateNode.setAttribute("password", p.getPassword()); //$NON-NLS-1$

		PEMParser pemParser = new PEMParser(new StringReader(
                federationMember.getPrivateKey()));
		Object object = pemParser.readObject();
	    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		JcaX509CertificateConverter converter2 = new JcaX509CertificateConverter().setProvider( "BC" );
	    KeyPair kp;
        kp = converter.getKeyPair((PEMKeyPair) object);
		pemParser.close();

		JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder("AES-128-CBC");
		builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		builder.setSecureRandom(new SecureRandom());
		PEMEncryptor encryptor = builder.build(p.getPassword().toCharArray());
		
		JcaMiscPEMGenerator gen = new JcaMiscPEMGenerator(kp.getPrivate(), encryptor);

        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);

        pemWriter.writeObject(gen);
        pemWriter.close();

        privateNode.setTextContent(writer.getBuffer().toString());
        
        // Public key
        Element certNode = doc.createElementNS(SECURITY_NAMESPACE,
                "Certificate"); //$NON-NLS-1$
        node.appendChild(certNode);

		pemParser = new PEMParser(new StringReader(
                federationMember.getCertificateChain()));
		do {
			object = pemParser.readObject();
			if (object == null) break;
			if (object instanceof X509CertificateHolder)
			{
				X509Certificate cert = converter2.getCertificate((X509CertificateHolder) object);
		        writer = new StringWriter();
		        pemWriter = new PemWriter(writer);
		        pemWriter.writeObject(new JcaMiscPEMGenerator( cert ) );
		        pemWriter.close();
		        certNode.setTextContent(writer.getBuffer().toString());
		        break;
			}
		} while (true);
		        
    }

    @SuppressWarnings("rawtypes")
    private void addProfiles() throws UnrecoverableKeyException,
            InvalidKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IllegalStateException,
            NoSuchProviderException, SignatureException, IOException,
            InternalErrorException {
        Element node = doc.createElementNS(RP_NAMESPACE,
                "AnonymousRelyingParty"); //$NON-NLS-1$
        node.setAttribute("provider", federationMember.getPublicId()); //$NON-NLS-1$
        node.setAttribute("defaultSigningCredentialRef", "cred-" //$NON-NLS-1$ //$NON-NLS-2$
                + federationMember.getPublicId());

        rootNode.insertBefore(node, trustEngineNode);

        node = doc.createElementNS(RP_NAMESPACE, "DefaultRelyingParty"); //$NON-NLS-1$
        node.setAttribute("provider", federationMember.getPublicId()); //$NON-NLS-1$
        node.setAttribute("defaultSigningCredentialRef", "cred-" //$NON-NLS-1$ //$NON-NLS-2$
                + federationMember.getPublicId());
        node.setAttribute("defaultAuthenticationMethod", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"); //$NON-NLS-1$ //$NON-NLS-2$
        addProfileDescriptor(federationMember, node);

        rootNode.insertBefore(node, trustEngineNode);

        addProfiles(entityGroupMember);

    }

    @SuppressWarnings("rawtypes")
    private void addProfiles(EntityGroupMember egm)
            throws UnrecoverableKeyException, InvalidKeyException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IllegalStateException, NoSuchProviderException, SignatureException,
            IOException, InternalErrorException {
        if (egm.getFederationMember() != null) {
            addProfiles(egm.getFederationMember());
        }
        for (Iterator it = federacioService.findChildren(egm).iterator(); it
                .hasNext();) {
            EntityGroupMember child = (EntityGroupMember) it.next();
            addProfiles(child);
        }

    }

    private void addProfiles(FederationMember fm) throws InternalErrorException {
        for (Iterator itSP = fm.getServiceProvider().iterator(); itSP.hasNext();) {
            FederationMember sp = (FederationMember) itSP.next();

            Element node = doc.createElementNS(RP_NAMESPACE, "RelyingParty"); //$NON-NLS-1$
            node.setAttribute("provider", fm.getPublicId()); //$NON-NLS-1$
            node.setAttribute("id", sp.getPublicId()); //$NON-NLS-1$
            String cred = fm.getPrivateKey() == null ? "cred-" //$NON-NLS-1$
                    + federationMember.getPublicId() : "cred-" //$NON-NLS-1$
                    + fm.getPublicId();
            node.setAttribute("defaultSigningCredentialRef", //$NON-NLS-1$
                    "cred-" + fm.getPublicId()); //$NON-NLS-1$
            node.setAttribute("defaultAuthenticationMethod", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"); //$NON-NLS-1$ //$NON-NLS-2$

            rootNode.insertBefore(node, trustEngineNode);

            addProfileDescriptor(fm, node);

        }

    }

    private void addProfileDescriptor(FederationMember fm, Element node) throws InternalErrorException {
        Collection<SAMLProfile> profiles = federacioService
                .findProfilesByFederationMember(fm);
        for (Iterator<SAMLProfile> it = profiles.iterator(); it.hasNext();) {
            SAMLProfile profile = (SAMLProfile) it.next();
            Element profileNode = doc.createElementNS(RP_NAMESPACE,
                    "ProfileConfiguration"); //$NON-NLS-1$
            node.appendChild(profileNode);
            SamlProfileEnumeration type = profile.getClasse();
            profileNode.setAttribute("xsi:type", "saml:" + type.getValue()); //$NON-NLS-1$ //$NON-NLS-2$

            generateSignAssertions(profile, profileNode);
            generateSignResponses(profile, profileNode);
            generateSignRequests(profile, profileNode);

            if (type.equals(SamlProfileEnumeration.SAML1_AR)) {
            } else if (type.equals(SamlProfileEnumeration.SAML1_AQ)) {
                generateOutboundArtifactType(profile, profileNode);
                generateAssertionLifetime(profile, profileNode);
            } else if (type.equals(SamlProfileEnumeration.SAML2_AR)) {
                generateEncryptAssertions(profile, profileNode);
                generateEncryptNameIds(profile, profileNode);
            } else if (type.equals(SamlProfileEnumeration.SAML1_AQ)) {
                generateOutboundArtifactType(profile, profileNode);
                generateAssertionLifetime(profile, profileNode);
                generateAssertionProxyCount(profile, profileNode);
                generateEncryptAssertions(profile, profileNode);
                generateEncryptNameIds(profile, profileNode);
            } else if (type.equals(SamlProfileEnumeration.SAML2_SSO)) {
                generateOutboundArtifactType(profile, profileNode);
                generateAssertionLifetime(profile, profileNode);
                generateMaximumSPSessionLifetime(profile, profileNode);
                generateAssertionProxyCount(profile, profileNode);
                generateEncryptAssertions(profile, profileNode);
                generateEncryptNameIds(profile, profileNode);
                generateSingleLogoutProfile (node);
            } else if (type.equals(SamlProfileEnumeration.SAML2_ECP)) {
                generateIncludeAttributeStatement(profile, profileNode);
                generateOutboundArtifactType(profile, profileNode);
                generateAssertionLifetime(profile, profileNode);
                generateLocalityAddress(profile, profileNode);
                generateLocalityDNSName(profile, profileNode);
                generateAssertionProxyCount(profile, profileNode);
                generateEncryptAssertions(profile, profileNode);
                generateEncryptNameIds(profile, profileNode);
            }

        }
    }

    private void generateSingleLogoutProfile(Element node) {
        Element profileNode = doc.createElementNS(RP_NAMESPACE,
                "ProfileConfiguration"); //$NON-NLS-1$
        node.appendChild(profileNode);
        profileNode.setAttribute("xsi:type", "saml:SAML2LogoutRequestProfile"); //$NON-NLS-1$ //$NON-NLS-2$
        profileNode.setAttribute("signResponses", "conditional"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	private void generateLocalityAddress(SAMLProfile profile,
            Element profileNode) {
        if (profile.getLocalityAddress() != null)
            profileNode.setAttribute("localityAddress", //$NON-NLS-1$
                    profile.getLocalityAddress());
    }

    private void generateLocalityDNSName(SAMLProfile profile,
            Element profileNode) {
        if (profile.getLocalityDNSName() != null)
            profileNode.setAttribute("localityDNSName", //$NON-NLS-1$
                    profile.getLocalityDNSName());
    }

    private String getSAMLRequirementText(SAMLRequirementEnumeration e) {
        if (SAMLRequirementEnumeration.ALWAYS.equals(e))
            return "always"; //$NON-NLS-1$
        if (SAMLRequirementEnumeration.CONDITIONAL.equals(e))
            return "conditional"; //$NON-NLS-1$
        if (SAMLRequirementEnumeration.NEVER.equals(e))
            return "never"; //$NON-NLS-1$
        return ""; //$NON-NLS-1$

    }

    private void generateSignAssertions(SAMLProfile profile, Element profileNode) {
        if (profile.getSignAssertions() != null)
            profileNode.setAttribute("signAssertions", //$NON-NLS-1$
                    getSAMLRequirementText(profile.getSignAssertions()));
    }

    private void generateSignResponses(SAMLProfile profile, Element profileNode) {
        if (profile.getSignResponses() != null)
            profileNode.setAttribute("signResponses", //$NON-NLS-1$
                    getSAMLRequirementText(profile.getSignResponses()));
    }

    private void generateSignRequests(SAMLProfile profile, Element profileNode) {
        if (profile.getSignRequests() != null)
            profileNode.setAttribute("signRequests", //$NON-NLS-1$
                    getSAMLRequirementText(profile.getSignRequests()));
    }

    private void generateIncludeAttributeStatement(SAMLProfile profile,
            Element profileNode) {
        if (profile.getIncludeAttributeStatement() != null)
            profileNode.setAttribute("includeAttributeStatement", profile //$NON-NLS-1$
                    .getIncludeAttributeStatement().toString());
    }

    private void generateAssertionLifetime(SAMLProfile profile,
            Element profileNode) {
        if (profile.getAssertionLifetime() != null)
            profileNode.setAttribute("assertionLifetime", //$NON-NLS-1$
                    profile.getAssertionLifetime());
    }

    private void generateOutboundArtifactType(SAMLProfile profile,
            Element profileNode) {
        if (profile.getOutboundArtifactType() != null)
            profileNode.setAttribute("outboundArtifactType", //$NON-NLS-1$
                    profile.getOutboundArtifactType());
    }

    private void generateEncryptNameIds(SAMLProfile profile, Element profileNode) {
        if (profile.getEncryptNameIds() != null)
            profileNode.setAttribute("encryptNameIds", //$NON-NLS-1$
                    getSAMLRequirementText(profile.getEncryptNameIds()));
    }

    private void generateEncryptAssertions(SAMLProfile profile,
            Element profileNode) {
        if (profile.getEncryptAssertions() != null)
            profileNode.setAttribute("encryptAssertions", //$NON-NLS-1$
                    getSAMLRequirementText(profile.getEncryptAssertions()));
    }

    private void generateAssertionProxyCount(SAMLProfile profile,
            Element profileNode) {
        if (profile.getAssertionProxyCount() != null)
            profileNode.setAttribute("assertionProxyCount", profile //$NON-NLS-1$
                    .getAssertionProxyCount().toString());
    }

    private void generateMaximumSPSessionLifetime(SAMLProfile profile,
            Element profileNode) {
        if (profile.getMaximumSPSessionLifetime() != null)
            profileNode.setAttribute("maximumSPSessionLifetime", //$NON-NLS-1$
                    profile.getMaximumSPSessionLifetime());
    }

    private void generateConditionAttributes(PolicyCondition cond,
            Element node, boolean ignoreCondition) {
        node.setPrefix("afp"); //$NON-NLS-1$
        if (!ignoreCondition && cond.getNegativeCondition() != null
                && cond.getNegativeCondition()) {
            node.setAttributeNS(XSI_NAMESPACE, "xsi:type", "NOT"); //$NON-NLS-1$ //$NON-NLS-2$
            Element childNode = doc.createElementNS(BASIC_NAMESPACE, "Rule"); //$NON-NLS-1$
            node.appendChild(childNode);
            generateConditionAttributes(cond, childNode, true);
        } else {
            ConditionType type = cond.getType();
            node.setAttributeNS(XSI_NAMESPACE, "xsi:type", type.getValue()); //$NON-NLS-1$
            if (type.equals(ConditionType.ANY)) {

            } else if (type.equals(ConditionType.AND)) {
                generateChildConditions(cond, node);
            } else if (type.equals(ConditionType.OR)) {
                generateChildConditions(cond, node);
            } else if (type.equals(ConditionType.ATTRIBUTE_REQUESTER_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
            } else if (type.equals(ConditionType.ATTRIBUTE_ISSUER_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
            } else if (type.equals(ConditionType.PRINCIPAL_NAME_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
            } else if (type.equals(ConditionType.AUTHENTICATION_METHOD_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
            } else if (type.equals(ConditionType.ATTRIBUTE_VALUE_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
                generateAttributeIdAttribute(cond, node);
            } else if (type.equals(ConditionType.ATTRIBUTE_SCOPE_STRING)) {
                generateValueAttribute(cond, node);
                generateCaseAttribute(cond, node);
                generateAttributeIdAttribute(cond, node);
            } else if (type.equals(ConditionType.ATTRIBUTE_REQUESTER_REGEX)) {
                generateRegexAttribute(cond, node);
            } else if (type.equals(ConditionType.ATTRIBUTE_ISSUER_REGEX)) {
                generateRegexAttribute(cond, node);
            } else if (type.equals(ConditionType.PRINCIPAL_NAME_REGEX)) {
                generateRegexAttribute(cond, node);
            } else if (type.equals(ConditionType.AUTHENTICATION_METHOD_REGEX)) {
                generateRegexAttribute(cond, node);
            } else if (type.equals(ConditionType.ATTRIBUTE_VALUE_REGEX)) {
                generateRegexAttribute(cond, node);
                generateAttributeIdAttribute(cond, node);
            } else if (type.equals(ConditionType.ATTRIBUTE_SCOPE_REGEX)) {
                generateRegexAttribute(cond, node);
                generateAttributeIdAttribute(cond, node);
            } else if (type.equals(ConditionType.SCRIPT)) {
                Element child = doc.createElementNS(BASIC_NAMESPACE, "Script"); //$NON-NLS-1$
                child.setTextContent(cond.getValue());
                node.appendChild(child);
            } else if (type
                    .equals(ConditionType.ATTRIBUTE_REQUESTER_IN_ENTITY_GROUP)) {
                generateGroupIdAttribute(cond, node);
            } else if (type
                    .equals(ConditionType.ATTRIBUTE_ISSUER_IN_ENTITY_GROUP)) {
                generateGroupIdAttribute(cond, node);
            } else if (type
                    .equals(ConditionType.ATTRIBUTE_ISSUER_NAME_IDFORMAT_EXACT_MATCH)) {
                generateNameIdAttribute(cond, node);
            } else if (type
                    .equals(ConditionType.ATTRIBUTE_REQUESTER_NAME_IDFORMAT_EXACT_MATCH)) {
                generateNameIdAttribute(cond, node);
            } else if (type
                    .equals(ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_EXACT_MATCH)) {
                generateAttributeNameAttribute(cond, node);
                generateAttributeValueAttribute(cond, node);
            } else if (type
                    .equals(ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_EXACT_MATCH)) {
                generateAttributeNameAttribute(cond, node);
                generateAttributeValueAttribute(cond, node);
            } else if (type
                    .equals(ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_REGEX_MATCH)) {
                generateAttributeNameAttribute(cond, node);
                generateAttributeValueRegExAttribute(cond, node);
            } else if (type
                    .equals(ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_REGEX_MATCH)) {
                generateAttributeNameAttribute(cond, node);
                generateAttributeValueRegExAttribute(cond, node);
            }
        }
    }

    private void generateAttributeValueRegExAttribute(PolicyCondition cond,
            Element node) {
        if (cond.getRegex() != null)
            node.setAttributeNS(AFP_NAMESPACE, "attributeValueRegex", //$NON-NLS-1$
                    cond.getRegex());
    }

    private void generateAttributeValueAttribute(PolicyCondition cond,
            Element node) {
        if (cond.getValue() != null)
            node.setAttributeNS(AFP_NAMESPACE, "attributeValue", //$NON-NLS-1$
                    cond.getValue());
    }

    private void generateAttributeNameAttribute(PolicyCondition cond,
            Element node) {
        if (cond.getNameId() != null)
            node.setAttributeNS(AFP_NAMESPACE, "attributeName", //$NON-NLS-1$
                    cond.getNameId());
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
            node.setAttributeNS(AFP_NAMESPACE, "attributeID", cond //$NON-NLS-1$
                    .getAttribute().getShortName());
    }

    private void generateValueAttribute(PolicyCondition cond, Element node) {
        if (cond.getValue() != null)
            node.setAttributeNS(AFP_NAMESPACE, "value", cond.getValue()); //$NON-NLS-1$
    }

    private void generateCaseAttribute(PolicyCondition cond, Element node) {
        if (cond.getIgnoreCase() != null)
            node.setAttributeNS(AFP_NAMESPACE, "ignoreCase", cond //$NON-NLS-1$
                    .getIgnoreCase().toString());
    }

    @SuppressWarnings("rawtypes")
    private void generateChildConditions(PolicyCondition cond, Element node) {
        for (Iterator it = cond.getChildrenCondition().iterator(); it.hasNext();) {
            PolicyCondition child = (PolicyCondition) it.next();
            Element childNode = doc.createElementNS(BASIC_NAMESPACE, "Rule"); //$NON-NLS-1$
            generateConditionAttributes(child, childNode, false);
            node.appendChild(childNode);
        }
    }
}
