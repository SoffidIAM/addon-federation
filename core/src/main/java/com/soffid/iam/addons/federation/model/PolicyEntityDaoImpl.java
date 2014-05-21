// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.PolicyCondition;

/**
 * @see com.soffid.iam.addons.federation.model.PolicyEntity
 */
public class PolicyEntityDaoImpl
    extends com.soffid.iam.addons.federation.model.PolicyEntityDaoBase
{
    /**
     * @see com.soffid.iam.addons.federation.model.PolicyEntityDao#toPolicy(com.soffid.iam.addons.federation.model.PolicyEntity, com.soffid.iam.addons.federation.common.Policy)
     */
    public void toPolicy(
        com.soffid.iam.addons.federation.model.PolicyEntity source,
        com.soffid.iam.addons.federation.common.Policy target)
    {
        // @todo verify behavior of toPolicy
        super.toPolicy(source, target);
        // WARNING! No conversion for target.attributePolicy (can't convert source.getAttributePolicy():com.soffid.iam.addons.federation.model.AttributePolicyEntity to com.soffid.iam.addons.federation.common.AttributePolicy
        // WARNING! No conversion for target.condition (can't convert source.getCondition():com.soffid.iam.addons.federation.model.PolicyConditionEntity to com.soffid.iam.addons.federation.common.PolicyCondition
        toPolicyCustom(source, target);
    }
    
    private void toPolicyCustom(
            com.soffid.iam.addons.federation.model.PolicyEntity source,
            com.soffid.iam.addons.federation.common.Policy target) {
    	
    	if (source.getCondition() != null) {
    		PolicyCondition condition = getPolicyConditionEntityDao().toPolicyCondition(source.getCondition());
    		target.setCondition(condition);
    	}
    	
    	if (source.getAttributePolicy()!=null) {
    		Set<AttributePolicy> attributePolicy = new HashSet<AttributePolicy>();
    		attributePolicy.addAll(getAttributePolicyEntityDao().toAttributePolicyList(source.getAttributePolicy()));
    		target.setAttributePolicy(attributePolicy);
    	}
    	
    	/*if (source.getIdentiyProvider() !=null) {
    		FederationMember idp = getFederationMemberEntityDao().toFederationMember(source.getIdentiyProvider());
    		target.setIdentityProvider(idp);    		
    	}*/
    }



    /**
     * @see com.soffid.iam.addons.federation.model.PolicyEntityDao#toPolicy(com.soffid.iam.addons.federation.model.PolicyEntity)
     */
    public com.soffid.iam.addons.federation.common.Policy toPolicy(final com.soffid.iam.addons.federation.model.PolicyEntity entity)
    {
        // @todo verify behavior of toPolicy
        return super.toPolicy(entity);
    }


    /**
     * Retrieves the entity object that is associated with the specified value object
     * from the object store. If no such entity object exists in the object store,
     * a new, blank entity is created
     */
    private com.soffid.iam.addons.federation.model.PolicyEntity loadPolicyEntityFromPolicy(com.soffid.iam.addons.federation.common.Policy policy)
    {
        com.soffid.iam.addons.federation.model.PolicyEntity policyEntity = null; 
        
        if (policy.getId() != null) {
        	policyEntity = this.load(policy.getId());
        }
        if (policyEntity == null)
        {
            policyEntity = newPolicyEntity();
        }
        return policyEntity;
    }

    
    /**
     * @see com.soffid.iam.addons.federation.model.PolicyEntityDao#policyToEntity(com.soffid.iam.addons.federation.common.Policy)
     */
    public com.soffid.iam.addons.federation.model.PolicyEntity policyToEntity(com.soffid.iam.addons.federation.common.Policy policy)
    {
        // @todo verify behavior of policyToEntity
        com.soffid.iam.addons.federation.model.PolicyEntity entity = this.loadPolicyEntityFromPolicy(policy);
        this.policyToEntity(policy, entity, true);
        return entity;
    }


    /**
     * @see com.soffid.iam.addons.federation.model.PolicyEntityDao#policyToEntity(com.soffid.iam.addons.federation.common.Policy, com.soffid.iam.addons.federation.model.PolicyEntity)
     */
    public void policyToEntity(
        com.soffid.iam.addons.federation.common.Policy source,
        com.soffid.iam.addons.federation.model.PolicyEntity target,
        boolean copyIfNull)
    {
        // nomes mantenim el nom
        super.policyToEntity(source, target, copyIfNull);
        policyToEntityCustom(source, target);
    }
    
    
	private void policyToEntityCustom(com.soffid.iam.addons.federation.common.Policy source,
			com.soffid.iam.addons.federation.model.PolicyEntity target) {
		
		// id
		if (source.getId() != null) {
			target.setId(source.getId());
		}
		
		// identityProvider
		/*if (source.getIdentityProvider() != null)  {
			FederationMember idp = source.getIdentityProvider();
			if (idp.getId()!=null) {
				FederationMemberEntity idpe = getFederationMemberEntityDao().federationMemberToEntity(idp);
				if (idpe instanceof IdentityProviderEntity) {
					target.setIdentiyProvider((IdentityProviderEntity)idpe); // casting
				}
			}
		}*/
		
		// attributePolicy
		if (source.getAttributePolicy() != null) {
	                Set<AttributePolicyEntity> attp = new HashSet<AttributePolicyEntity>();
			attp.addAll(getAttributePolicyEntityDao().attributePolicyToEntityList(source.getAttributePolicy()));
			target.setAttributePolicy(attp);
		}
		
		// condition
		if (source.getCondition() != null) {
			PolicyCondition polcon = source.getCondition();
			PolicyConditionEntity polconE = getPolicyConditionEntityDao().policyConditionToEntity(polcon);
			target.setCondition(polconE);
		}
		
		
	}

}