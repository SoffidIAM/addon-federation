package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
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
import es.caib.seycon.ng.exception.InternalErrorException;

public class UserAttributesGenerator {
	public Map<String, Object> generateAttributes(ServletContext ctx, TokenInfo t) throws AttributeResolutionException, AttributeFilteringException, InternalErrorException, IOException {
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
			String openIdName = attribute.getOpenidName();
			if (openIdName == null || openIdName.isEmpty())
				openIdName = attribute.getShortName();
			
			BaseAttribute samlAttribute = att.get(attribute.getShortName());
			if (samlAttribute != null && !samlAttribute.getValues().isEmpty())
				if (samlAttribute.getValues().size() == 1)
					result.put(openIdName, samlAttribute.getValues().iterator().next());
				else
					result.put(openIdName, new LinkedList( samlAttribute.getValues()));
		}
	
		return result;
		
	}

}
