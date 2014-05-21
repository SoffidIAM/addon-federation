// license-header java merge-point
/**
 * This is only generated once! It will never be overwritten.
 * You can (and have to!) safely modify it by hand.
 */
package com.soffid.iam.addons.federation.model;
/**
 * @see com.soffid.iam.addons.federation.model.EntityGroupEntity
 */
public class EntityGroupEntityDaoImpl
    extends com.soffid.iam.addons.federation.model.EntityGroupEntityDaoBase
{
    /**
     * @see com.soffid.iam.addons.federation.model.EntityGroupEntityDao#toEntityGroup(com.soffid.iam.addons.federation.model.EntityGroupEntity, com.soffid.iam.addons.federation.common.EntityGroup)
     */
    public void toEntityGroup(
        com.soffid.iam.addons.federation.model.EntityGroupEntity source,
        com.soffid.iam.addons.federation.common.EntityGroup target)
    {
        // @todo verify behavior of toEntityGroup
        super.toEntityGroup(source, target);
        // WARNING! No conversion for target.members (can't convert source.getMembers():com.soffid.iam.addons.federation.model.FederationMemberEntity to java.util.Collection
    }


    /**
     * @see com.soffid.iam.addons.federation.model.EntityGroupEntityDao#toEntityGroup(com.soffid.iam.addons.federation.model.EntityGroupEntity)
     */
    public com.soffid.iam.addons.federation.common.EntityGroup toEntityGroup(final com.soffid.iam.addons.federation.model.EntityGroupEntity entity)
    {
        // @todo verify behavior of toEntityGroup
        return super.toEntityGroup(entity);
    }


    /**
     * Retrieves the entity object that is associated with the specified value object
     * from the object store. If no such entity object exists in the object store,
     * a new, blank entity is created
     */
	private com.soffid.iam.addons.federation.model.EntityGroupEntity loadEntityGroupEntityFromEntityGroup(
			com.soffid.iam.addons.federation.common.EntityGroup entityGroup) {
		com.soffid.iam.addons.federation.model.EntityGroupEntity entity = null;
		if (entityGroup.getId() != null) {
			entity = load(entityGroup.getId());
		}
		if (entity == null) {
			entity = newEntityGroupEntity();
		}
		return entity;
	}
    
    /**
     * @see com.soffid.iam.addons.federation.model.EntityGroupEntityDao#entityGroupToEntity(com.soffid.iam.addons.federation.common.EntityGroup)
     */
    public com.soffid.iam.addons.federation.model.EntityGroupEntity entityGroupToEntity(com.soffid.iam.addons.federation.common.EntityGroup entityGroup)
    {
        // @todo verify behavior of entityGroupToEntity
        com.soffid.iam.addons.federation.model.EntityGroupEntity entity = this.loadEntityGroupEntityFromEntityGroup(entityGroup);
        this.entityGroupToEntity(entityGroup, entity, true);
        return entity;
    }


    /**
     * @see com.soffid.iam.addons.federation.model.EntityGroupEntityDao#entityGroupToEntity(com.soffid.iam.addons.federation.common.EntityGroup, com.soffid.iam.addons.federation.model.EntityGroupEntity)
     */
    public void entityGroupToEntity(
        com.soffid.iam.addons.federation.common.EntityGroup source,
        com.soffid.iam.addons.federation.model.EntityGroupEntity target,
        boolean copyIfNull)
    {
        // @todo verify behavior of entityGroupToEntity
        super.entityGroupToEntity(source, target, copyIfNull);
    }

}