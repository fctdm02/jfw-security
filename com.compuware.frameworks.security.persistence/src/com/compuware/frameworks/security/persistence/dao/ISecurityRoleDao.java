/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2011 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.persistence.dao;

import java.util.Collection;
import java.util.Set;

import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.AbstractGroup;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipal;
import com.compuware.frameworks.security.service.api.model.SecurityRole;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;


/**
 * 
 * @author tmyers
 */
public interface ISecurityRoleDao extends ICompuwareSecurityDao {
	
	/**
	 * 
	 * @param securityRoleName
	 * @param multiTenancyRealm
	 * @return <code>true</code> if a security role with the given role 
	 * name already exists for the given realm; <code>false</code> otherwise.
	 */
	boolean securityRoleExists(String securityRoleName, MultiTenancyRealm multiTenancyRealm);
	
	/**
	 * @param roleName
	 * @param displayName
	 * @param description
	 * @param isAssignedByDefault
	 * @param isDeletable
	 * @param isModifiable
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	SecurityRole createSecurityRole(
	   String roleName,
	   String displayName,
	   String description,
	   boolean isAssignedByDefault,
	   boolean isDeletable,
	   boolean isModifiable,
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectAlreadyExistsException,
	   ValidationException;

	/**
	 * @param roleName
	 * @param displayName
	 * @param description
	 * @param isAssignedByDefault
	 * @param includedRoles
	 * @param isDeletable
	 * @param isModifiable
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	SecurityRole createSecurityRole(
	   String roleName,
	   String displayName,
	   String description,
	   boolean isAssignedByDefault,
	   Set<SecurityRole> includedRoles,
	   boolean isDeletable,
	   boolean isModifiable,
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectAlreadyExistsException,
	   ValidationException;
	
	/**
	 * @param roleName 
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectNotFoundException
	 */
	SecurityRole getSecurityRole(
		String roleName,	
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ObjectNotFoundException;

	/**
	 * 
	 * @param multiTenancyRealm
	 * @return All security roles for the given realm.
	 */
	Collection<SecurityRole> getAllSecurityRoles(MultiTenancyRealm multiTenancyRealm);
		
    /**
     * 
     * @param multiTenancyRealm
     * @return All security roles for the given realm that are marked as 'assign by default'.
     */
    Collection<SecurityRole> getAllDefaultSecurityRoles(MultiTenancyRealm multiTenancyRealm);	
	
    /**
     * 
     * @return
     */
    Collection<SecurityRole> getAllSecurityRoles();
	
	/**
	 * 
	 * @param user
	 * @param multiTenancyRealm
	 * @return
	 */
	Collection<SecurityRole> getAllSecurityRolesForUser(AbstractUser user, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;		

	/**
	 * 
	 * @param group
	 * @param multiTenancyRealm
	 * @return
	 */
	Collection<SecurityRole> getAllSecurityRolesForGroup(AbstractGroup group, MultiTenancyRealm multiTenancyRealm) ;		
	
	/**
	 * 
	 * @param securityPrincipal
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectNotFoundException
	 */
	Collection<SecurityRole> getAllSecurityRolesForSecurityPrincipal(SecurityPrincipal securityPrincipal, MultiTenancyRealm multiTenancyRealm);

	/**
	 *
	 * @param securityRoleName The Security Role to retrieve associated SecurityPrincipals for.
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return All SecurityPrincipals associated with the given SecurityRole.  
	 * These SecurityPrincipals can either be instances of AbstractUser (SecurityUser, SystemUser or ShadowSecurityUser) 
	 * or AbstractGroup(SecurityGroup or ShadowSecurityGroup)
	 * @throws ObjectNotFoundException If no SecurityRole named <code>securityRoleName</code> exists in the given realm. 
	 */
	Collection<SecurityPrincipal> getAllSecurityPrincipalsForSecurityRole(String roleName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;
	
    /**
    *
    * @param securityRoleName The Security Role to retrieve the included SecurityRoles for.
    * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
    * @return All SecurityRoles that are "included" (as part of the Role Hierarchy) for the given SecurityRole.  
    * @throws ObjectNotFoundException If no SecurityRole named <code>securityRoleName</code> exists in the given realm. 
    */
   Collection<SecurityRole> getAllIncludedSecurityRolesForSecurityRole(String roleName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;	
}