/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2010 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.migration;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.access.annotation.Secured;

import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.MigrationGroup;
import com.compuware.frameworks.security.service.api.model.MigrationRecord;
import com.compuware.frameworks.security.service.api.model.MigrationUser;

/**
 * 
 * @author tmyers
 *
 */
public interface IMigrationService {

    /** */
    String CANNOT_MIGRATE_USER_BECAUSE_USER_WITH_SAME_PRINCIPAL_NAME_ALREADY_EXISTS_REASON = "1";

    /** */
    String CANNOT_MIGRATE_USER_BECAUSE_GROUP_WITH_SAME_PRINCIPAL_NAME_ALREADY_EXISTS_REASON = "2";

    /** */
    String CANNOT_MIGRATE_GROUP_BECAUSE_USER_WITH_SAME_PRINCIPAL_NAME_ALREADY_EXISTS_REASON = "3";

    /** */
    String CANNOT_MIGRATE_GROUP_BECAUSE_GROUP_WITH_SAME_PRINCIPAL_NAME_ALREADY_EXISTS_REASON = "4";
        
    /** */
    String PRINCIPAL_NAME_CANNOT_BE_EMPTY_REASON = "5";

    /** */
    String PRINCIPAL_NAME_LENGTH_TOO_SHORT_REASON = "6";

    /** */
    String PRINCIPAL_NAME_LENGTH_TOO_LONG_REASON = "7";

    /** */
    String PRINCIPAL_NAME_HAS_LEADING_SPACES_REASON = "8";

    /** */
    String PRINCIPAL_NAME_HAS_TRAILING_SPACES_REASON = "9";
    
	/**
	 *  Create security users and groups specified by a set of nested hash maps.
	 *    
	 * @param sourceRepositoryName A unique name for the information in <code>sourceRepositoryMap</code>. e.g. "VSM", "VAS1", "VAS2", etc.
	 * @param userList The list of users to migrate.
	 * @param groupList The list of groups to migrate.
	 * @param realmName The top level grouping for all domain objects for a given organization.
	 * @return The list of users/groups that could not be migrated (reason is given) in the form of MigrationRecord domain objects
	 * @throws ObjectNotFoundException 
	 */
	@Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
	List<MigrationRecord> migrateUsersAndGroups(
       String sourceRepositoryName, 
       ArrayList<MigrationUser> userList,
       ArrayList<MigrationGroup> groupList,
       String realmName) 
	throws 
	    ObjectNotFoundException;
	
	/**
	 * 
	 * @param realmName
	 * @return The set of source repository names that represent all migration records for the given realm.
	 * @throws ObjectNotFoundException 
	 */
	List<String> getSourceRepositories(
	    String realmName)
    throws 
        ObjectNotFoundException;
	
	/**
	 * @param sourceRepositoryName
	 * @param realmName
	 * @return A collection of <code>MigrationRecords</code> that represent users/groups
	 * that could not be created because they already existed in the given 
	 * realm
	 * <b>NOTE:</b> It is assumed some sort of "Migration Reconcilation GUI" will the
	 * administrator to view this list and act accordingly.
	 * @throws ObjectNotFoundException
	 */
	List<MigrationRecord> getMigrationRecords(
		String sourceRepositoryName, 
		String realmName) 
	throws 
		ObjectNotFoundException;
}