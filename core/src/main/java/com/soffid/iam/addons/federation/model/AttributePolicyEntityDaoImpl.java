// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.model;

import java.util.Collection;
import java.util.Iterator;

import com.soffid.iam.addons.federation.common.AttributePolicyCondition;

/**
 * @see com.soffid.iam.addons.federation.model.AttributePolicyEntity
 */
public class AttributePolicyEntityDaoImpl
    extends com.soffid.iam.addons.federation.model.AttributePolicyEntityDaoBase
{
    /**
     * @see com.soffid.iam.addons.federation.model.AttributePolicyEntityDao#toAttributePolicy(com.soffid.iam.addons.federation.model.AttributePolicyEntity, com.soffid.iam.addons.federation.common.AttributePolicy)
     */
    public void toAttributePolicy(
        com.soffid.iam.addons.federation.model.AttributePolicyEntity source,
        com.soffid.iam.addons.federation.common.AttributePolicy target)
    {
        // @todo verify behavior of toAttributePolicy
        super.toAttributePolicy(source, target);
        // WARNING! No conversion for target.policy (can't convert source.getPolicy():com.soffid.iam.addons.federation.model.PolicyEntity to com.soffid.iam.addons.federation.common.Policy
        // WARNING! No conversion for target.attribute (can't convert source.getAttribute():com.soffid.iam.addons.federation.model.AttributeEntity to com.soffid.iam.addons.federation.common.Attribute
        toAttributePolicyCustom(source, target);        
    }
    
	private void toAttributePolicyCustom(com.soffid.iam.addons.federation.model.AttributePolicyEntity source,
			com.soffid.iam.addons.federation.common.AttributePolicy target) {
		// falta convertir attribute i attributeCondition
		
		if (source.getAttribute() != null) {
			target.setAttribute(getAttributeEntityDao().toAttribute(source.getAttribute()));
		}

		if (source.getAttributeCondition() != null) {
			target.setAttributePolicyCondition(getAttributeConditionEntityDao().toAttributePolicyCondition(
					source.getAttributeCondition()));
		}

	}

    /**
     * @see com.soffid.iam.addons.federation.model.AttributePolicyEntityDao#toAttributePolicy(com.soffid.iam.addons.federation.model.AttributePolicyEntity)
     */
    public com.soffid.iam.addons.federation.common.AttributePolicy toAttributePolicy(final com.soffid.iam.addons.federation.model.AttributePolicyEntity entity)
    {
        // @todo verify behavior of toAttributePolicy
        return super.toAttributePolicy(entity);
    }


    /**
     * Retrieves the entity object that is associated with the specified value object
     * from the object store. If no such entity object exists in the object store,
     * a new, blank entity is created
     */
	private com.soffid.iam.addons.federation.model.AttributePolicyEntity loadAttributePolicyEntityFromAttributePolicy(
			com.soffid.iam.addons.federation.common.AttributePolicy attributePolicy) {

		com.soffid.iam.addons.federation.model.AttributePolicyEntity attributePolicyEntity = null;
		if (attributePolicy.getId() != null) {
			attributePolicyEntity = this.load(attributePolicy.getId());
		}
		if (attributePolicyEntity == null) {
			attributePolicyEntity = newAttributePolicyEntity();
		}
		return attributePolicyEntity;
	}
    
    /**
     * @see com.soffid.iam.addons.federation.model.AttributePolicyEntityDao#attributePolicyToEntity(com.soffid.iam.addons.federation.common.AttributePolicy)
     */
    public com.soffid.iam.addons.federation.model.AttributePolicyEntity attributePolicyToEntity(com.soffid.iam.addons.federation.common.AttributePolicy attributePolicy)
    {
        // @todo verify behavior of attributePolicyToEntity
        com.soffid.iam.addons.federation.model.AttributePolicyEntity entity = this.loadAttributePolicyEntityFromAttributePolicy(attributePolicy);
        this.attributePolicyToEntity(attributePolicy, entity, true);
        return entity;
    }


    /**
     * @see com.soffid.iam.addons.federation.model.AttributePolicyEntityDao#attributePolicyToEntity(com.soffid.iam.addons.federation.common.AttributePolicy, com.soffid.iam.addons.federation.model.AttributePolicyEntity)
     */
    public void attributePolicyToEntity(
        com.soffid.iam.addons.federation.common.AttributePolicy source,
        com.soffid.iam.addons.federation.model.AttributePolicyEntity target,
        boolean copyIfNull) 
    {
    	// Atributs: policy, attribute i attributeCondition
        super.attributePolicyToEntity(source, target, copyIfNull);
        
        if (source.getPolicyId()!=null) {
        	PolicyEntity policy = getPolicyEntityDao().findById(source.getPolicyId());
        	target.setPolicy(policy);
        }
        
        // attribute
        if (source.getAttribute() != null && source.getAttribute().getId()!=null) {
        	// en principi l'atribut ja existeix a la bbdd i en té id
        	AttributeEntity att = getAttributeEntityDao().findById(source.getAttribute().getId());
        	target.setAttribute(att);
        }
        // attributeCondition
        AttributePolicyCondition attpol = source.getAttributePolicyCondition();
        AttributeConditionEntity attpole = getAttributeConditionEntityDao().attributePolicyConditionToEntity(attpol);
        target.setAttributeCondition(attpole);
        
    }


}