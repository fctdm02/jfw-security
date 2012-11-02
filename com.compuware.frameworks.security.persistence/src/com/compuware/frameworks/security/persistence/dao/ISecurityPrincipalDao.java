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

import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.AbstractGroup;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityGroup;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipal;
import com.compuware.frameworks.security.service.api.model.SecurityUser;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.SystemUser;
import com.compuware.frameworks.security.service.api.model.exception.PasswordPolicyException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;


/**
 * 
 * @author tmyers
 */
public interface ISecurityPrincipalDao extends ICompuwareSecurityDao {
	
	/**
	 * 
	 * @param securityPrincipalName
	 * @param multiTenancyRealm
	 * @return <code>true</code> if a security principal with the given principal 
	 * name already exists for the given realm; <code>false</code> otherwise.
	 */
	boolean securityPrincipalExists(String securityPrincipalName, MultiTenancyRealm multiTenancyRealm);

	/**
	 * 
	 * @param securityPrincipalName
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectNotFoundException
	 */
	SecurityPrincipal getSecurityPrincipalByPrincipalName(
	   String securityPrincipalName,	
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectNotFoundException;
	
	/**
	 * 
	 * @param username
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectNotFoundException
	 */
	AbstractUser getUserByUsername(
	   String username,	
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectNotFoundException;
	
	/**
	 * It should be that a given username can exist only once in a realm, but can exist
	 * in different realms (each modeling a different person/system entity for that realm)
	 * 
	 * @param username The realm-specific natural key for a given user (e.g. tmyers)
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return The user identified by the given username (natural key) for the given realm
	 * @throws ObjectNotFoundException
	 */
	SystemUser getSystemUserByUsername(
		String username, 
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ObjectNotFoundException;

	/**
	 * It should be that a given username can exist only once in a realm, but can exist
	 * in different realms (each modeling a different person/system entity for that realm)
	 * 
	 * @param username The realm-specific natural key for a given user (e.g. tmyers)
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return The user identified by the given username (natural key) for the given realm
	 * @throws ObjectNotFoundException
	 */
	SecurityUser getSecurityUserByUsername(
		String username, 
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ObjectNotFoundException;

	/**
	 * @param username
	 * @param multiTenancyRealm
	 * @return The given ShadowSecurityUser, if it exists, <code>null</code> otherwise.
	 */
	ShadowSecurityUser getShadowSecurityUserByUsername(
		String username, 
		MultiTenancyRealm multiTenancyRealm);
	
	/**
	 * @param user
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return All security groups that the given user belongs to.
	 */
	Collection<SecurityGroup> getSecurityGroupsForUser(
		AbstractUser user, 
		MultiTenancyRealm multiTenancyRealm)	
	throws 
		ObjectNotFoundException;
	
	/**
	 * 
	 * @param groupname
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectNotFoundException
	 */
	SecurityGroup getSecurityGroupByGroupname(
	   String groupname,	
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectNotFoundException;

	/**
	 * 
	 * @param groupname
	 * @param multiTenancyRealm
	 * @return The given ShadowSecurityGroup, if it exists, <code>null</code> otherwise.
	 */
	ShadowSecurityGroup getShadowSecurityGroupByGroupname(
	   String groupname,	
	   MultiTenancyRealm multiTenancyRealm);
	
	/**
	 * 
	 * @param groupname
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectNotFoundException
	 */
	AbstractGroup getGroupByGroupname(
	   String groupname,	
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectNotFoundException;

	
	/**
	 * Retrieves a collection of all SecurityUsers that meet the given non-null/non-empty criteria: 
	 * 
	 * @param firstNameCriteria 
	 * @param lastNameCriteria
	 * @param primaryEmailAddressCriteria
	 * @param isActiveCriteria If null, then ignore this criteria; If Boolean.TRUE, only return active users; If Boolean.FALSE, only return inactive users
	 * @param isOrQuery If true, the search is a logical OR query, logical AND otherwise.
	 * @param maxResults The maximum number of results that can be returned.
	 * @param multiTenancyRealm
	 * @return A collection of all SecurityUsers that meet the specified search criteria. 
	 * For example, if <b>only</b> 'Myers' is specified as <code>lastNameCriteria</code>
	 * and <code>true</code> is specified as <code>isActiveCriteria</code> and <code>false</code> is 
	 * specified as <code>isOrQuery</code>, then an equivalent SQL-like query where clause might look like:
	 * <pre>
	 * FROM USERS WHERE LAST_NAME LIKE '%Myers%' AND IS_ACTIVE = '1' 
	 * </pre>
	 * and return something like:   
	 * <pre>
	 * [mibtdm0=[firstName=Thomas,lastName=Myers,primaryEmailAddressCriteria=thomas.myers@compuware.com]]
	 * [mibsem0=[firstName=Steven,lastName=Myers,primaryEmailAddressCriteria=steven.myers@compuware.com]]
	 * </pre>
	 * assuming that only Thomas and Steven are the only active users with the string 'Myers' 
	 * anywhere in their last name. 
	 * @throws ValidationException If no search criteria are specified.
	 */
	Collection<SecurityUser> getAllSecurityUsersByCriteria(
		String firstNameCriteria,
		String lastNameCriteria,
		String primaryEmailAddressCriteria,
		Boolean isActiveCriteria,
		boolean isOrQuery,
		int firstResult,
		int maxResults,
		MultiTenancyRealm multiTenancyRealm) throws ValidationException;
	
	/**
	 * 
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return All SecurityUsers for the given realm (active or inactive)
	 */
	Collection<SecurityUser> getAllSecurityUsers(MultiTenancyRealm multiTenancyRealm);	

	/**
	 * 
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return All Active SecurityUsers for the given realm only
	 */
	Collection<SecurityUser> getAllActiveSecurityUsers(MultiTenancyRealm multiTenancyRealm);	

	/**
	 * 
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return All Inactive SecurityUsers for the given realm only
	 */
	Collection<SecurityUser> getAllInactiveSecurityUsers(MultiTenancyRealm multiTenancyRealm);	

	/**
	 * 
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return All system users for the given realm
	 */
	Collection<SystemUser> getAllSystemUsers(MultiTenancyRealm multiTenancyRealm);	

	/**
	 * 
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return
	 */
	Collection<AbstractUser> getAllUsers(MultiTenancyRealm multiTenancyRealm);	
	
	/**
	 * 
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return All groups for the given realm
	 */
	Collection<SecurityGroup> getAllSecurityGroups(MultiTenancyRealm multiTenancyRealm);	

    /**
     * 
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return All groups for the given realm that are marked as 'assign by default'
     */
    Collection<SecurityGroup> getAllDefaultSecurityGroups(MultiTenancyRealm multiTenancyRealm);    
	
	/**
	 * 
	 * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
	 * @return
	 */
	Collection<AbstractGroup> getAllGroups(MultiTenancyRealm multiTenancyRealm);	

	/**
	 * 
	 * @param securityUser
	 * @return Persisted SecurityUser
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 * @throws PasswordPolicyException
	 */
	SecurityUser createSecurityUser(SecurityUser securityUser)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException,
	   PasswordPolicyException;	
	
	/**
	 * 
	 * @param username
	 * @param multiTenancyRealm
	 * @return Persisted ShadowSecurityUser
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	ShadowSecurityUser createShadowSecurityUser(
	   String username,
	   MultiTenancyRealm multiTenancyRealm)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException;
	
	/**
	 * 
	 * @param systemUser
	 * @return Persisted SystemUser
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	SystemUser createSystemUser(SystemUser systemUser)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException;

	/**
	 * 
	 * @param groupname
	 * @param description
	 * @param assignByDefault
	 * @param isDeletable
	 * @param isModifiable
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	SecurityGroup createSecurityGroup(
	   String groupname,
	   String description,
	   boolean assignByDefault,
	   boolean isDeletable,
	   boolean isModifiable,
	   MultiTenancyRealm multiTenancyRealm)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException;

	/**
	 * 
	 * @param groupname
	 * @param description
	 * @param assignByDefault
	 * @param parentGroup
     * @param isDeletable
     * @param isModifiable
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	SecurityGroup createSecurityGroup(
	   String groupname,
	   String description,
	   boolean assignByDefault,
	   SecurityGroup parentGroup,
       boolean isDeletable,
       boolean isModifiable,	   
	   MultiTenancyRealm multiTenancyRealm)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException;
	
	/**
	 * 
	 * @param groupname
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	ShadowSecurityGroup createShadowSecurityGroup(
	   String groupname,
	   MultiTenancyRealm multiTenancyRealm)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException;
	
   /**
    * 
    * @param groupnameCriteria
    * @param firstResult
    * @param maxResults
    * @param multiTenancyRealm
    * @return
    * @throws ValidationException
    */
   Collection<AbstractGroup> getAllGroupsByCriteria(
       String groupnameCriteria,
       int firstResult,
       int maxResults,
       MultiTenancyRealm multiTenancyRealm) 
   throws 
       ValidationException;   	
}