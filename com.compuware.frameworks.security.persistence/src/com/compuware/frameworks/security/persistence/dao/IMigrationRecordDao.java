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

import java.util.List;

import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.model.MigrationRecord;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public interface IMigrationRecordDao extends ICompuwareSecurityDao {

    /**
     * 
     * @param migrationRecord
     * @return
     */
    boolean migrationRecordExists(MigrationRecord migrationRecord);
    
	/**
	 * 
	 * @param sourceRepositoryName
	 * @param principalName
	 * @param nameValuePairs
	 * @param reason
	 * @param multiTenancyRealm
	 * @return
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	MigrationRecord createUserMigrationRecord(
		String sourceRepositoryName,
		String principalName,
	    String nameValuePairs,
	    String reason,
	    MultiTenancyRealm multiTenancyRealm)
	throws 
		ObjectAlreadyExistsException, 
		ValidationException;

    /**
     * 
     * @param sourceRepositoryName
     * @param principalName
     * @param nameValuePairs
     * @param reason
     * @param multiTenancyRealm
     * @return
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    MigrationRecord createGroupMigrationRecord(
        String sourceRepositoryName,
        String principalName,
        String nameValuePairs,
        String reason,
        MultiTenancyRealm multiTenancyRealm)
    throws 
        ObjectAlreadyExistsException, 
        ValidationException;
	
	/**
	 * 
	 * @param multiTenancyRealm
	 * @return
	 */
	List<String> getMigrationRecordSourceRepositoryNames(MultiTenancyRealm multiTenancyRealm);
	
	/**
	 * @param sourceRepositoryName
	 * @param multiTenancyRealm
	 * @return
	 */
	List<MigrationRecord> getAllMigrationRecordsForSourceRepository(String sourceRepositoryName, MultiTenancyRealm multiTenancyRealm);
}