// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.AttributePolicyCondition;
import com.soffid.iam.addons.federation.common.Policy;
import com.soffid.iam.addons.federation.common.PolicyCondition;

/**
 * @see com.soffid.iam.addons.federation.model.PolicyConditionEntity
 */
public class PolicyConditionEntityDaoImpl extends com.soffid.iam.addons.federation.model.PolicyConditionEntityDaoBase {
	/**
	 * @see com.soffid.iam.addons.federation.model.PolicyConditionEntityDao#toPolicyCondition(com.soffid.iam.addons.federation.model.PolicyConditionEntity,
	 *      com.soffid.iam.addons.federation.common.PolicyCondition)
	 */
	public void toPolicyCondition(com.soffid.iam.addons.federation.model.PolicyConditionEntity source, com.soffid.iam.addons.federation.common.PolicyCondition target) {
		// @todo verify behavior of toPolicyCondition
		super.toPolicyCondition(source, target);

		if (source.getAttributeCondition() != null) {
			source.getAttributeCondition().getId();
		}

		if (source.getAttribute() != null) {
			AttributeEntity att = source.getAttribute();
			target.setAttribute(getAttributeEntityDao().toAttribute(att));
		}

		// tot Ok: falta el childrenCondition
		if (source.getCondition() != null) {
			target.setChildrenCondition(toPolicyConditionList(source.getCondition()));
		}
	}

	/**
	 * @see com.soffid.iam.addons.federation.model.PolicyConditionEntityDao#toPolicyCondition(com.soffid.iam.addons.federation.model.PolicyConditionEntity)
	 */
	public com.soffid.iam.addons.federation.common.PolicyCondition toPolicyCondition(final com.soffid.iam.addons.federation.model.PolicyConditionEntity entity) {
		// @todo verify behavior of toPolicyCondition
		return super.toPolicyCondition(entity);
	}

	/**
	 * Retrieves the entity object that is associated with the specified value
	 * object from the object store. If no such entity object exists in the
	 * object store, a new, blank entity is created
	 */
	private com.soffid.iam.addons.federation.model.PolicyConditionEntity loadPolicyConditionEntityFromPolicyCondition(
			com.soffid.iam.addons.federation.common.PolicyCondition policyCondition) {

		com.soffid.iam.addons.federation.model.PolicyConditionEntity policyConditionEntity = null;
		if (policyCondition.getId() != null) {
			policyConditionEntity = this.load(policyCondition.getId());
		}
		if (policyConditionEntity == null) {
			policyConditionEntity = newPolicyConditionEntity();
		}
		return policyConditionEntity;

	}

	/**
	 * @see com.soffid.iam.addons.federation.model.PolicyConditionEntityDao#policyConditionToEntity(com.soffid.iam.addons.federation.common.PolicyCondition)
	 */
	public com.soffid.iam.addons.federation.model.PolicyConditionEntity policyConditionToEntity(com.soffid.iam.addons.federation.common.PolicyCondition policyCondition) {
		// @todo verify behavior of policyConditionToEntity
		com.soffid.iam.addons.federation.model.PolicyConditionEntity entity = this.loadPolicyConditionEntityFromPolicyCondition(policyCondition);
		this.policyConditionToEntity(policyCondition, entity, true);
		return entity;
	}

	public Policy clonaPolicy(Policy original, boolean comNova) {
		// copiem la base
		Policy nova = new Policy(original);

		if (original.getCondition() != null) {
			// el clonem
			PolicyCondition clonPC = clonaPC(original.getCondition(), comNova);
			nova.setCondition(clonPC);
		}

		if (original.getAttributePolicy() != null) {
			Collection attPolicy = original.getAttributePolicy();
			ArrayList clonAttributePolicy = new ArrayList(attPolicy.size());
			for (Iterator<AttributePolicy> it = attPolicy.iterator(); it.hasNext();) {
				AttributePolicy attPolOriginal = it.next();
				// Creem el clon
				AttributePolicy clonAttPol = new AttributePolicy(attPolOriginal);
				if (comNova)
					clonAttPol.setId(null);// nou
				// clonem els AttributePolicyCondition de l'original
				AttributePolicyCondition clonAPC = clonaAC(attPolOriginal.getAttributePolicyCondition(), comNova);
				clonAttPol.setAttributePolicyCondition(clonAPC);
				clonAttributePolicy.add(clonAttPol);
			}
			nova.setAttributePolicy(clonAttributePolicy);
		}

		return nova;
	}

	public PolicyCondition clonaPC(PolicyCondition original, boolean comNova) {
		PolicyCondition pc = new PolicyCondition(original);
		if (comNova)
			pc.setId(null); // nou
		if (original.getChildrenCondition() != null) {
			Collection children = original.getChildrenCondition();
			Collection childrenNous = new ArrayList();
			if (children != null)
				for (Iterator<PolicyCondition> it = children.iterator(); it.hasNext();) {
					PolicyCondition f = it.next();
					childrenNous.add(clonaPC(f, comNova));
				}
			pc.setChildrenCondition(childrenNous);
		}
		return pc;
	}

	public AttributePolicyCondition clonaAC(AttributePolicyCondition original, boolean comNova) {
		AttributePolicyCondition pc = new AttributePolicyCondition(original);
		if (comNova)
			pc.setId(null);// nou
		if (original.getChildrenCondition() != null) {
			Collection children = original.getChildrenCondition();
			Collection childrenNous = new ArrayList();
			if (children != null)
				for (Iterator<AttributePolicyCondition> it = children.iterator(); it.hasNext();) {
					AttributePolicyCondition f = it.next();
					childrenNous.add(clonaPC(f, comNova));
				}
			pc.setChildrenCondition(childrenNous);
		}
		return pc;
	}

	/**
	 * @see com.soffid.iam.addons.federation.model.PolicyConditionEntityDao#policyConditionToEntity(com.soffid.iam.addons.federation.common.PolicyCondition,
	 *      com.soffid.iam.addons.federation.model.PolicyConditionEntity)
	 */
	public void policyConditionToEntity(com.soffid.iam.addons.federation.common.PolicyCondition source,
			com.soffid.iam.addons.federation.model.PolicyConditionEntity target, boolean copyIfNull) {
		// @todo verify behavior of policyConditionToEntity
		super.policyConditionToEntity(source, target, copyIfNull);

		if (source.getId() != null)
			target.setId(source.getId());

		// tot Ok: falta el childrenCondition
		if (source.getChildrenCondition() != null) {
			List<PolicyConditionEntity> condicionsFilles = policyConditionToEntityList(source.getChildrenCondition());
			// Establim qui és el seu pare..
			for (Iterator<PolicyConditionEntity> it = condicionsFilles.iterator(); it.hasNext();) {
				PolicyConditionEntity pc = it.next();
				pc.setAttributeCondition(target); // ens establim com el seu
													// pare..
			}
			target.getCondition().clear();
			target.getCondition().addAll(condicionsFilles);
		}

		// I el atribut
		if (source.getAttribute() != null && source.getAttribute().getId() != null) {
			AttributeEntity ate = getAttributeEntityDao().findById(source.getAttribute().getId());
			target.setAttribute(ate);
		}

	}

        /**
         * @see com.soffid.iam.addons.federation.model.AttributeConditionEntityDao#toAttributePolicyCondition(com.soffid.iam.addons.federation.model.AttributeConditionEntity,
         *      com.soffid.iam.addons.federation.common.AttributePolicyCondition)
         */
        @SuppressWarnings("unchecked")
        public void toAttributePolicyCondition(com.soffid.iam.addons.federation.model.AttributeConditionEntity source,
                        com.soffid.iam.addons.federation.common.AttributePolicyCondition target) {
                // @todo verify behavior of toAttributePolicyCondition
                super.toAttributePolicyCondition(source, target);

                // tot Ok: falta el childrenCondition i l'atribut
                if (source.getCondition() != null) {
                	target.setChildrenCondition(new LinkedList<PolicyCondition>());
                	target.getChildrenCondition().addAll(toAttributePolicyConditionList((Collection)source.getCondition()));
                }

                // Atribut
                if (source.getAttribute() != null) {
                        AttributeEntity att = source.getAttribute();
                        target.setAttribute(getAttributeEntityDao().toAttribute(att));
                }

        }

        /**
         * @see com.soffid.iam.addons.federation.model.AttributeConditionEntityDao#toAttributePolicyCondition(com.soffid.iam.addons.federation.model.AttributeConditionEntity)
         */
        public com.soffid.iam.addons.federation.common.AttributePolicyCondition toAttributePolicyCondition(
                        final com.soffid.iam.addons.federation.model.AttributeConditionEntity entity) {
                // @todo verify behavior of toAttributePolicyCondition
                return super.toAttributePolicyCondition(entity);
        }

        /**
         * Retrieves the entity object that is associated with the specified value
         * object from the object store. If no such entity object exists in the
         * object store, a new, blank entity is created
         */
        private com.soffid.iam.addons.federation.model.AttributeConditionEntity loadAttributeConditionEntityFromAttributePolicyCondition(
                        com.soffid.iam.addons.federation.common.AttributePolicyCondition attributePolicyCondition) {

                com.soffid.iam.addons.federation.model.AttributeConditionEntity attributeConditionEntity = null;
                if (attributePolicyCondition.getId() != null) {
                        attributeConditionEntity = (AttributeConditionEntity) this.load(attributePolicyCondition.getId());
                }
                if (attributeConditionEntity == null) {
                        attributeConditionEntity = newAttributeConditionEntity();
                }
                return attributeConditionEntity;

        }

        /**
         * @see com.soffid.iam.addons.federation.model.AttributeConditionEntityDao#attributePolicyConditionToEntity(com.soffid.iam.addons.federation.common.AttributePolicyCondition)
         */
        public com.soffid.iam.addons.federation.model.AttributeConditionEntity attributePolicyConditionToEntity(
                        com.soffid.iam.addons.federation.common.AttributePolicyCondition attributePolicyCondition) {
                // @todo verify behavior of attributePolicyConditionToEntity
                com.soffid.iam.addons.federation.model.AttributeConditionEntity entity = this
                                .loadAttributeConditionEntityFromAttributePolicyCondition(attributePolicyCondition);
                this.attributePolicyConditionToEntity(attributePolicyCondition, entity, true);
                return entity;
        }

        /**
         * @see com.soffid.iam.addons.federation.model.AttributeConditionEntityDao#attributePolicyConditionToEntity(com.soffid.iam.addons.federation.common.AttributePolicyCondition,
         *      com.soffid.iam.addons.federation.model.AttributeConditionEntity)
         */
        public void attributePolicyConditionToEntity(com.soffid.iam.addons.federation.common.AttributePolicyCondition source,
                        com.soffid.iam.addons.federation.model.AttributeConditionEntity target, boolean copyIfNull) {
                // @todo verify behavior of attributePolicyConditionToEntity
                super.attributePolicyConditionToEntity(source, target, copyIfNull);

                // tot Ok: falta el childrenCondition
                if (source.getChildrenCondition() != null) {
                        Collection condicionsFilles = attributePolicyConditionToEntityList((Collection)source.getChildrenCondition());
                        // Establim qui és el seu pare..
                        for (Iterator<AttributeConditionEntity> it = condicionsFilles.iterator(); it.hasNext();) {
                                AttributeConditionEntity pc = it.next();
                                // ens establim com el seu pare..
                                pc.setAttributeCondition(target);
                        }
                        target.getCondition().clear();
                        for (PolicyCondition condition: source.getChildrenCondition()) {
                        	target.getCondition().add(attributePolicyConditionToEntity((AttributePolicyCondition) condition));
                        }
                        target.getCondition().addAll(condicionsFilles);
                }
                // I el atribut
                if (source.getAttribute() != null && source.getAttribute().getId() != null) {
                        AttributeEntity ate = getAttributeEntityDao().findById(source.getAttribute().getId());
                        target.setAttribute(ate);
                }
        }


}