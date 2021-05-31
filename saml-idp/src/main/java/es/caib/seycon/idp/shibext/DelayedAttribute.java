package es.caib.seycon.idp.shibext;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.sync.engine.extobj.AttributeReference;
import com.soffid.iam.sync.engine.extobj.AttributeReferenceParser;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.ValueObjectMapper;
import com.soffid.iam.sync.intf.ExtensibleObject;

import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.AbstractScopedAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML1Base64AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML1StringAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML1XMLObjectAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML2Base64AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML2StringAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML2XMLObjectAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.ShibbolethAttributeFilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeScopeRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeScopeStringMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeValueRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeValueStringMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeInMetadataMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class DelayedAttribute extends BasicAttribute<String> {
	private ObjectTranslator translator;
	private ExtensibleObject eo;
	private Attribute attribute;
	boolean resolved = false;

	public DelayedAttribute(String name, ObjectTranslator translator, ExtensibleObject eo, Attribute attribute) {
		super(name);
		this.translator = translator;
		this.eo = eo;
		this.attribute = attribute;
		getValues().add("");
	}
	
	
	public void resolve() {
		if ( !resolved) {
			doResolve();
			setValues(doResolve());
			resolved = true;
		}
	}

	protected Collection<String> doResolve() {
        Object r;
		try { 
			AttributeReference ar = AttributeReferenceParser.parse(eo, attribute.getValue());
			r = ar.getValue();
		} catch (Exception ear) {
			try {
				r = translator.eval(attribute.getValue(), eo);
			} catch (InternalErrorException e) {
				throw new RuntimeException ("Error evaluating attribute "+attribute.getName(), e);
			}
		}

		if (r == null)
        	return new LinkedList<String>();
        else if (r instanceof Collection)
        	return (Collection<String>) r;
        else if (r instanceof byte[])
         	return Collections.singleton( Base64.encodeBytes((byte[]) r, Base64.DONT_BREAK_LINES) );
        else  
        	return Collections.singleton( new ValueObjectMapper().toSingleString(r) );
	}


	@Override
	public Collection<String> getValues() {
		StackTraceElement[] st = Thread.currentThread().getStackTrace();
		int i = 0;
		while (i < st.length) {
			if (st[i].getClassName().equals(getClass().getName())) {
				if ( st[i+1].getClassName().equals( AttributeValueRegexMatchFunctor.class.getName()) ||
						st[i+1].getClassName().equals( AttributeValueStringMatchFunctor.class.getName()) ||
						st[i+1].getClassName().equals( AttributeValueRegexMatchFunctor.class.getName()) ||
						st[i+1].getClassName().equals( AttributeScopeRegexMatchFunctor.class.getName()) ||
						st[i+1].getClassName().equals( AttributeScopeStringMatchFunctor.class.getName()) ||
						st[i+1].getClassName().equals( AttributeInMetadataMatchFunctor.class.getName()) ||
						st[i+1].getClassName().equals( SAML1StringAttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( SAML1Base64AttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( SAML1XMLObjectAttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( SAML2StringAttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( SAML2Base64AttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( SAML2XMLObjectAttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( AbstractScopedAttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( ShibbolethAttributeFilteringEngine.class.getName()) ||
						st[i+1].getClassName().equals( UserAttributesGenerator.class.getName()) ||
						st[i+1].getClassName().equals( AbstractScopedAttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( AbstractScopedAttributeEncoder.class.getName()) ||
						st[i+1].getClassName().equals( AbstractScopedAttributeEncoder.class.getName())) 
				{
					resolve();
				}
				break;
			}
			i++;
		}
		return super.getValues();
	}

}
