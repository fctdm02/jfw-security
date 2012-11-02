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

import com.compuware.frameworks.security.service.api.management.exception.NonDeletableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.PasswordPolicy;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;


/**
 * 
 * @author tmyers
 */
public interface IMultiTenancyRealmDao extends ICompuwareSecurityDao {

	/**
	 * 
	 * @param realmName
	 * @return <code>true</code> if a MultiTenancyRealm with the given
	 * name already exists in the security repository; <code>false</code> otherwise.
	 */
	boolean multiTenancyRealmExists(String realmName);

    /**
     * @param passwordPolicyName
     * @param realmName
     * @return <code>true</code> if a PasswordPolicy with the given
     * name already exists in the security repository for the given realm; <code>false</code> otherwise.
     */
	boolean passwordPolicyExists(String passwordPolicyName, String realmName);
	
	/**
	 * 
	 * @param realmName
	 * @param description
	 * @param ldapBaseDn
	 * @param passwordPolicies
     * @param isDeletable
     * @param isModifiable
	 * @return
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	MultiTenancyRealm createMultiTenancyRealm(
		String realmName,
		String description,
		String ldapBaseDn,
		Set<PasswordPolicy> passwordPolicies,
        boolean isDeletable,
        boolean isModifiable) 
	throws 
		ObjectAlreadyExistsException, 
		ValidationException;

	/**
	 * 
	 * @param passwordPolicyName
	 * @param description
	 * @param ageLimit
	 * @param historyLimit
	 * @param minNumberOfDigits
	 * @param minNumberOfChars
	 * @param minNumberOfSpecialChars
	 * @param minPasswordLength
	 * @param maxNumberUnsuccessfulLoginAttempts
	 * @param isDeletable
	 * @param isModifiable
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
    PasswordPolicy createPasswordPolicy(
        String passwordPolicyName,
        String description,
        int ageLimit,
        int historyLimit,
        int minNumberOfDigits,
        int minNumberOfChars,
        int minNumberOfSpecialChars,
        int minPasswordLength,
        int maxNumberUnsuccessfulLoginAttempts,
        boolean isDeletable,
        boolean isModifiable,
        MultiTenancyRealm multiTenancyRealm)
    throws 
        ObjectAlreadyExistsException, 
        ValidationException;

    /**
     * 
     * @param passwordPolicyName
     * @param multiTenancyRealm
     * @throws ObjectNotFoundException
     * @throws NonDeletableObjectException
     */
    void deletePasswordPolicy(String passwordPolicyName, MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException, 
        NonDeletableObjectException;
	
	/**
	 * 
	 * @param realmName
	 * @return
	 * @throws MultiTenancyRealmNotFoundException
	 */
	MultiTenancyRealm getMultiTenancyRealmByRealmName(
		String realmName) 
	throws 
		ObjectNotFoundException;
	
	/**
	 * 
	 * @return
	 */
	Collection<MultiTenancyRealm> getAllMultiTenancyRealms();
}