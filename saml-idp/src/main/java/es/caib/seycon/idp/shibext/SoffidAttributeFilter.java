package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.Map.Entry;
import java.util.concurrent.locks.Lock;
import java.util.regex.Pattern;

import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContext;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.Policy;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserData;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.service.SecretStoreService;
import com.soffid.iam.sync.service.ServerService;
import com.soffid.iam.utils.Security;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML1StringAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML2StringAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.AttributeFilterPolicy;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.AttributeRule;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.MatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.ShibbolethAttributeFilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.ShibbolethFilteringContext;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AbstractMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AndMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AnyMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeIssuerRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeIssuerStringMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeRequesterRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeRequesterStringMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeValueRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AttributeValueStringMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AuthenticationMethodRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.AuthenticationMethodStringMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.NotMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.OrMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.PrincipalRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.basic.PrincipalStringMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeIssuerEntityAttributeExactMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeIssuerEntityAttributeRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeIssuerInEntityGroupMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeIssuerNameIDFormatExactMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeRequesterEntityAttributeExactMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeRequesterEntityAttributeRegexMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeRequesterInEntityGroupMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.provider.match.saml.AttributeRequesterNameIDFormatExactMatchFunctor;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethAttributeResolver;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition.AttributeDefinition;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition.SimpleAttributeDefinition;
import edu.internet2.middleware.shibboleth.common.config.BaseReloadableService;
import edu.internet2.middleware.shibboleth.common.config.attribute.filtering.match.basic.PrincipalNameRegexMatchFunctionBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.service.ServiceException;
import edu.internet2.middleware.shibboleth.common.session.Session;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class SoffidAttributeFilter extends ShibbolethAttributeFilteringEngine {
	
	Log log = LogFactory.getLog(getClass());
	
	Map<String, FilterData> cache = new Hashtable<>();
	
	protected FilterData getData() {
		try {
			FilterData data = cache.get(Security.getCurrentTenantName());
			if (data == null) 
				data = loadData();
			else if (data.lastRefresh < System.currentTimeMillis() - 10000) { // 10 seconds data
				ServerService server = new RemoteServiceLocator().getServerService();
			    String config = server.getConfig("saml.policy.lastchange");
			    long lastUpdate = 0;
			    try {
			    	lastUpdate = Long.decode(config);
			    } catch (Exception e) {}
		        if (lastUpdate > data.lastRefresh - 5000) // 5 seconds clock skew
		        	data = loadData();
		        else
		        	data.lastRefresh = System.currentTimeMillis();
			}
		
			return data;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private FilterData loadData() throws InternalErrorException, IOException {
		FilterData data = new FilterData();
		data.lastRefresh = System.currentTimeMillis();
		data.policies = new RemoteServiceLocator().getFederacioService().findPolicies();
		data.attributeFilterPolicies = transform (data.policies);
		
		cache.put(Security.getCurrentTenantName(), data);
    	return data;
	}

	private Collection<AttributeFilterPolicy> transform(Collection<Policy> policies) {
		List<AttributeFilterPolicy> t = new LinkedList<>();
		for ( Policy policy: policies)
			t.add(transform(policy));
		AttributeFilterPolicy tp = new AttributeFilterPolicy("releaseTransientIdToAnyone");
		tp.setPolicyRequirementRule(new AnyMatchFunctor());
		AttributeRule tr = new AttributeRule("transientId");
		tp.getAttributeRules().add(tr);
		tr.setPermitValueRule(new AnyMatchFunctor());
		t.add(tp);
		return t;
	}

	private AttributeFilterPolicy transform(Policy policy) {
		AttributeFilterPolicy t = new AttributeFilterPolicy(policy.getName());
		t.setPolicyRequirementRule( transform(policy.getCondition()));
		for (AttributePolicy att: policy.getAttributePolicy())
			t.getAttributeRules().add(transformAttribute(att));
		return t;
	}

	private AttributeRule transformAttribute(AttributePolicy att) {
		AttributeRule t = new AttributeRule(att.getAttribute().getShortName());
		if (Boolean.TRUE.equals( att.getAttributePolicyCondition().getAllow()))
			t.setPermitValueRule( transform(att.getAttributePolicyCondition()) );
		else
			t.setDenyValueRule( transform (att.getAttributePolicyCondition()));
		return t;
	}

	private MatchFunctor transform(PolicyCondition condition) {
		AbstractMatchFunctor t = new AnyMatchFunctor();
		if (condition.getType() == ConditionType.ANY) 
		{
			t = new AnyMatchFunctor();
		}
		else if (condition.getType() == ConditionType.AND) {
			List<MatchFunctor> l = new LinkedList<>();
			for (PolicyCondition child: condition.getChildrenCondition())
				l.add(transform(child));
			t = new AndMatchFunctor(l);
		}
		else if (condition.getType() == ConditionType.OR) {
			List<MatchFunctor> l = new LinkedList<>();
			for (PolicyCondition child: condition.getChildrenCondition())
				l.add(transform(child));
			t = new OrMatchFunctor(l);
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_EXACT_MATCH) {
			AttributeIssuerEntityAttributeExactMatchFunctor tt = new AttributeIssuerEntityAttributeExactMatchFunctor();
			tt.setName(condition.getAttribute().getShortName());
			tt.setNameFormat(condition.getAttributeNameFormat());
			tt.setValue(condition.getValue());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_REGEX_MATCH) {
			AttributeIssuerEntityAttributeRegexMatchFunctor tt = new AttributeIssuerEntityAttributeRegexMatchFunctor();
			tt.setName(condition.getAttribute().getShortName());
			tt.setNameFormat(condition.getAttributeNameFormat());
			try {
				tt.setValueRegex(Pattern.compile( condition.getRegex()) );
				t = tt;
			} catch (Exception e) {
				return new NotMatchFunctor(new AnyMatchFunctor()) ;
			}
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_ISSUER_IN_ENTITY_GROUP) {
			AttributeIssuerInEntityGroupMatchFunctor tt = new AttributeIssuerInEntityGroupMatchFunctor();
			tt.setEntityGroup(condition.getGroupId());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_ISSUER_NAME_IDFORMAT_EXACT_MATCH) {
			AttributeIssuerNameIDFormatExactMatchFunctor tt = new AttributeIssuerNameIDFormatExactMatchFunctor();
			tt.setNameIdFormat(condition.getAttributeNameFormat());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_ISSUER_STRING) {
			AttributeIssuerStringMatchFunctor tt = new AttributeIssuerStringMatchFunctor();
			tt.setCaseSensitive(Boolean.FALSE.equals( condition.getIgnoreCase()) );
			tt.setMatchString(condition.getValue());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_ISSUER_REGEX) {
			AttributeIssuerRegexMatchFunctor tt = new AttributeIssuerRegexMatchFunctor();
			tt.setRegularExpression(condition.getRegex() );
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_EXACT_MATCH) {
			AttributeRequesterEntityAttributeExactMatchFunctor tt = new AttributeRequesterEntityAttributeExactMatchFunctor();
			tt.setName(condition.getAttribute().getShortName());
			tt.setNameFormat(condition.getAttributeNameFormat());
			tt.setValue(condition.getValue());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_REGEX_MATCH) {
			AttributeRequesterEntityAttributeRegexMatchFunctor tt = new AttributeRequesterEntityAttributeRegexMatchFunctor();
			tt.setName(condition.getAttribute().getShortName());
			tt.setNameFormat(condition.getAttributeNameFormat());
			try {
				tt.setValueRegex(Pattern.compile( condition.getRegex()) );
				t = tt;
			} catch (Exception e) {
				return new NotMatchFunctor(new AnyMatchFunctor()) ;
			}
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_REQUESTER_IN_ENTITY_GROUP) {
			AttributeRequesterInEntityGroupMatchFunctor tt = new AttributeRequesterInEntityGroupMatchFunctor();
			tt.setEntityGroup(condition.getGroupId());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_REQUESTER_NAME_IDFORMAT_EXACT_MATCH) {
			AttributeRequesterNameIDFormatExactMatchFunctor tt = new AttributeRequesterNameIDFormatExactMatchFunctor();
			tt.setNameIdFormat(condition.getAttributeNameFormat());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_REQUESTER_STRING) {
			AttributeRequesterStringMatchFunctor tt = new AttributeRequesterStringMatchFunctor();
			tt.setCaseSensitive(Boolean.FALSE.equals( condition.getIgnoreCase()) );
			tt.setMatchString(condition.getValue());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_REQUESTER_REGEX) {
			AttributeRequesterRegexMatchFunctor tt = new AttributeRequesterRegexMatchFunctor();
			tt.setRegularExpression(condition.getRegex() );
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_VALUE_REGEX) {
			AttributeValueRegexMatchFunctor tt = new AttributeValueRegexMatchFunctor();
			tt.setRegularExpression(condition.getRegex());
			tt.setAttributeId(condition.getAttribute().getShortName());
			t = tt;
		}
		else if (condition.getType() == ConditionType.ATTRIBUTE_VALUE_STRING) {
			AttributeValueStringMatchFunctor tt = new AttributeValueStringMatchFunctor();
			tt.setAttributeId(condition.getAttribute().getShortName());
			tt.setCaseSensitive(Boolean.FALSE.equals( condition.getIgnoreCase()) );
			tt.setMatchString(condition.getValue() );
			t = tt;
		}
		else if (condition.getType() == ConditionType.AUTHENTICATION_METHOD_REGEX) {
			AuthenticationMethodRegexMatchFunctor tt = new AuthenticationMethodRegexMatchFunctor();
			tt.setRegularExpression(condition.getRegex());
			t = tt;
		}
		else if (condition.getType() == ConditionType.AUTHENTICATION_METHOD_STRING) {
			AuthenticationMethodStringMatchFunctor tt = new AuthenticationMethodStringMatchFunctor();
			tt.setMatchString(condition.getValue());
			tt.setCaseSensitive(Boolean.FALSE.equals( condition.getIgnoreCase()) );
			t = tt;
		}
		else if (condition.getType() == ConditionType.PRINCIPAL_NAME_REGEX) {
			PrincipalRegexMatchFunctor tt = new PrincipalRegexMatchFunctor();
			tt.setRegularExpression(condition.getRegex());
			t = tt;
		}
		else if (condition.getType() == ConditionType.PRINCIPAL_NAME_STRING) {
			PrincipalStringMatchFunctor tt = new PrincipalStringMatchFunctor();
			tt.setMatchString(condition.getValue() );
			tt.setCaseSensitive(Boolean.FALSE.equals( condition.getIgnoreCase()) );
			t = tt;
		}
		else
		{
			throw new RuntimeException("Unsupported condition "+condition.getType().toString());
		}
		
		if (Boolean.TRUE.equals(condition.getNegativeCondition()))
			t = new NotMatchFunctor(t);
				
		return t;
	}

	@Override
	public Map<String, BaseAttribute> filterAttributes(Map<String, BaseAttribute> attributes,
			SAMLProfileRequestContext context) throws AttributeFilteringException {
		FilterData data = getData();
		// TODO Auto-generated method stub
        log.debug(getId() + " filtering "+attributes.size()+"attributes for principal "+context.getPrincipalName());

        if (attributes.size() == 0) {
            return new HashMap<String, BaseAttribute>();
        }

        if (data == null || data.attributeFilterPolicies == null) {
            log.debug("No filter policies were loaded in "+getId()+", filtering out all attributes for "+context.getPrincipalName());
            return new HashMap<String, BaseAttribute>();
        }

        ShibbolethFilteringContext filterContext = new ShibbolethFilteringContext(attributes, context);
        Lock readLock = getReadWriteLock().readLock();
        readLock.lock();
        try{
            for (AttributeFilterPolicy filterPolicy : data.attributeFilterPolicies) {
                filterAttributes(filterContext, filterPolicy);
                runDenyRules(filterContext);
            }
        }finally{
            readLock.unlock();
        }

        Iterator<Entry<String, BaseAttribute>> attributeEntryItr = attributes.entrySet().iterator();
        Entry<String, BaseAttribute> attributeEntry;
        BaseAttribute attribute;
        Collection retainedValues;
        while (attributeEntryItr.hasNext()) {
            attributeEntry = attributeEntryItr.next();
            attribute = attributeEntry.getValue();
            retainedValues = filterContext.getRetainedValues(attribute.getId(), false);
            attribute.getValues().clear();
            attribute.getValues().addAll(retainedValues);
            if (attribute.getValues().size() == 0) {
                log.debug("Removing attribute from return set, no more values: "+attribute.getId());
                attributeEntryItr.remove();
            }else{
                log.debug("Attribute "+attribute.getId()+" has "+attribute
                        .getValues().size()+" values after filtering");
            }
        }

        log.info("Filtered attributes for principal "+context.getPrincipalName()+".  The following attributes remain: "+attributes.keySet());
        return attributes;
	}

	@Override
	protected void onNewContextCreated(ApplicationContext newServiceContext) throws ServiceException {
		
	}
}

class FilterData {
	public Collection<Policy> policies;
	long lastRefresh;
	Collection<AttributeFilterPolicy> attributeFilterPolicies;
}