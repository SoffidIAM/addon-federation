package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringEngine;
import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.shibext.DelayedAttribute;
import es.caib.seycon.ng.exception.InternalErrorException;

public class UserAttributesGenerator {
	public Map<String, Object> generateAttributes(ServletContext ctx, TokenInfo t) throws AttributeResolutionException, AttributeFilteringException, InternalErrorException, IOException {
		return generateAttributes(ctx, t, true);
	}
	public Map<String, Object> generateAttributes(ServletContext ctx, TokenInfo t, boolean openid) throws AttributeResolutionException, AttributeFilteringException, InternalErrorException, IOException {
		AttributeResolver<SAMLProfileRequestContext> resolver = (AttributeResolver<SAMLProfileRequestContext>)
				HttpServletHelper.getAttributeResolver(ctx);
		
		AttributeFilteringEngine<SAMLProfileRequestContext> filter =
				(AttributeFilteringEngine<SAMLProfileRequestContext>)
				HttpServletHelper.getAttributeFilterEnginer(ctx);

		DummySamlRequestContext context = new DummySamlRequestContext(t, ctx);
		Map<String, BaseAttribute> att;
		att = resolver.resolveAttributes(context);
		att = filter.filterAttributes(att, context);

		Map<String,Object> result = new HashMap<String, Object>();
		
		for ( Attribute attribute: new RemoteServiceLocator().getFederacioService().findAtributs(null, null, null) )
		{
			String name;
			if (openid) {
				name = attribute.getOpenidName();
				if (name == null || name.isEmpty())
					name = attribute.getShortName();
			} else {
				name = attribute.getRadiusIdentifier();
			}
			
			BaseAttribute samlAttribute = att.get(attribute.getShortName());
			if (name != null && !name.trim().isEmpty() &&
					samlAttribute != null && !samlAttribute.getValues().isEmpty())
				if (samlAttribute instanceof DelayedAttribute && ((DelayedAttribute) samlAttribute).isArray())
					result.put(name, new LinkedList( samlAttribute.getValues()));
				else if (samlAttribute.getValues().size() == 1)
					result.put(name, samlAttribute.getValues().iterator().next());
				else
					result.put(name, new LinkedList( samlAttribute.getValues()));
		}
	
		return result;
		
	}

	public List<String> generateAttributeNames(ServletContext ctx, String user, String authMethod, String serviceProvider) throws AttributeResolutionException, AttributeFilteringException, InternalErrorException, IOException {
		AttributeResolver<SAMLProfileRequestContext> resolver = (AttributeResolver<SAMLProfileRequestContext>)
				HttpServletHelper.getAttributeResolver(ctx);
		
		AttributeFilteringEngine<SAMLProfileRequestContext> filter =
				(AttributeFilteringEngine<SAMLProfileRequestContext>)
				HttpServletHelper.getAttributeFilterEnginer(ctx);

		DummySamlRequestContext2 context = new DummySamlRequestContext2(ctx, user, authMethod, serviceProvider);
		Map<String, BaseAttribute> att;
		att = resolver.resolveAttributes(context);
		att = filter.filterAttributes(att, context);

		List<String> result = new LinkedList<String>();
		
		for ( Attribute attribute: new RemoteServiceLocator().getFederacioService().findAtributs(null, null, null) )
		{
			BaseAttribute samlAttribute = att.get(attribute.getShortName());
			if (samlAttribute != null)
				result.add(attribute.getName());
		}
	
		return result;
		
	}

}
