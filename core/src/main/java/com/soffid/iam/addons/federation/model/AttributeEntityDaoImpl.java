// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.model;
/**
 * @see com.soffid.iam.addons.federation.model.AttributeEntity
 */
public class AttributeEntityDaoImpl
    extends com.soffid.iam.addons.federation.model.AttributeEntityDaoBase
{
    /**
     * @see com.soffid.iam.addons.federation.model.AttributeEntityDao#toAttribute(com.soffid.iam.addons.federation.model.AttributeEntity, com.soffid.iam.addons.federation.common.Attribute)
     */
    public void toAttribute(
        com.soffid.iam.addons.federation.model.AttributeEntity source,
        com.soffid.iam.addons.federation.common.Attribute target)
    {
        super.toAttribute(source, target);
        // res més a fer
    }


    /**
     * @see com.soffid.iam.addons.federation.model.AttributeEntityDao#toAttribute(com.soffid.iam.addons.federation.model.AttributeEntity)
     */
    public com.soffid.iam.addons.federation.common.Attribute toAttribute(final com.soffid.iam.addons.federation.model.AttributeEntity entity)
    {
        // @todo verify behavior of toAttribute
        return super.toAttribute(entity);
    }


    /**
     * Retrieves the entity object that is associated with the specified value object
     * from the object store. If no such entity object exists in the object store,
     * a new, blank entity is created
     */
	private com.soffid.iam.addons.federation.model.AttributeEntity loadAttributeEntityFromAttribute(com.soffid.iam.addons.federation.common.Attribute attribute) {
		com.soffid.iam.addons.federation.model.AttributeEntity attributeEntity = null;

		if (attribute.getId() != null) {
			attributeEntity = this.load(attribute.getId());
		}
		if (attributeEntity == null) {
			attributeEntity = newAttributeEntity();
		}
		return attributeEntity;
	}
    
    /**
     * @see com.soffid.iam.addons.federation.model.AttributeEntityDao#attributeToEntity(com.soffid.iam.addons.federation.common.Attribute)
     */
    public com.soffid.iam.addons.federation.model.AttributeEntity attributeToEntity(com.soffid.iam.addons.federation.common.Attribute attribute)
    {
        // @todo verify behavior of attributeToEntity
        com.soffid.iam.addons.federation.model.AttributeEntity entity = this.loadAttributeEntityFromAttribute(attribute);
        this.attributeToEntity(attribute, entity, true);
        return entity;
    }


    /**
     * @see com.soffid.iam.addons.federation.model.AttributeEntityDao#attributeToEntity(com.soffid.iam.addons.federation.common.Attribute, com.soffid.iam.addons.federation.model.AttributeEntity)
     */
    public void attributeToEntity(
        com.soffid.iam.addons.federation.common.Attribute source,
        com.soffid.iam.addons.federation.model.AttributeEntity target,
        boolean copyIfNull)
    {
        // @todo verify behavior of attributeToEntity
        super.attributeToEntity(source, target, copyIfNull);
        
        if (source.getId()!=null) {
        	target.setId(source.getId());
        }
        
    }

}