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

import java.io.Serializable;

import com.compuware.frameworks.security.service.api.management.exception.NonDeletableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.NonModifiableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.exception.StaleObjectException;
import com.compuware.frameworks.security.service.api.model.DomainObject;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public interface ICompuwareSecurityDao {

	/**
	 * 
	 * @param clazz
	 * @param id
	 * @return
	 * @throws ObjectNotFoundException
	 */
	@SuppressWarnings("rawtypes")
    DomainObject getDomainObjectById(Class clazz, Serializable id) throws ObjectNotFoundException;

	/**
	 * 
	 * @param clazz
	 * @param id
	 * @return
	 */
	@SuppressWarnings("rawtypes")
    DomainObject getDomainObjectByIdNullIfNotFound(Class clazz, Serializable id);
	
    /**
     * 
     * @param domainObject
     * @throws ValidationException
     * @throws ObjectAlreadyExistsException
     */
	void save(DomainObject domainObject) throws ValidationException, ObjectAlreadyExistsException;
    
	/**
	 * 
	 * @param domainObject
	 * @throws ObjectNotFoundException
	 * @throws ValidationException
	 * @throws StaleObjectException
	 * @throws NonModifiableObjectException
	 */
	void update(DomainObject domainObject) 
	throws 
	    ObjectNotFoundException, 
	    ValidationException, 
	    StaleObjectException,
	    NonModifiableObjectException;
	
	/**
	 * 
	 * @param domainObject
	 * @throws ObjectNotFoundException
	 * @throws NonDeletableObjectException
	 */
	void delete(DomainObject domainObject)
	throws
	    ObjectNotFoundException,
	    NonDeletableObjectException;
	
	/**
	 * 
	 * @param domainObject
	 * @throws ObjectNotFoundException
	 */
	void evict(DomainObject domainObject) throws ObjectNotFoundException;	
}