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
package com.compuware.frameworks.security.service.server.migration;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.log4j.Logger;

import com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao;
import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.exception.StaleObjectException;
import com.compuware.frameworks.security.service.api.migration.IMigrationService;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.DomainObject;
import com.compuware.frameworks.security.service.api.model.MigrationGroup;
import com.compuware.frameworks.security.service.api.model.MigrationRecord;
import com.compuware.frameworks.security.service.api.model.MigrationUser;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityGroup;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipal;
import com.compuware.frameworks.security.service.api.model.SecurityRole;
import com.compuware.frameworks.security.service.api.model.exception.PasswordPolicyException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;
import com.compuware.frameworks.security.service.server.AbstractService;
import com.compuware.frameworks.security.service.server.ServiceProvider;

/**
 * 
 * @author tmyers
 * 
 */
public final class MigrationServiceImpl extends AbstractService implements IMigrationService {

	/* */
	private final Logger logger = Logger.getLogger(MigrationServiceImpl.class);
	
	/** */
	private IManagementService managementService;
	
	/** */
	private IMigrationRecordDao migrationRecordDao;
		
	/**
	 * @param managementService
	 * @param eventService
	 * @param auditService
	 * @param multiTenancyRealmDao
	 * @param migrationRecordDao
	 */
	public MigrationServiceImpl(
			IManagementService managementService,
			IEventService eventService,
			IAuditService auditService,
			IMultiTenancyRealmDao multiTenancyRealmDao,
			IMigrationRecordDao migrationRecordDao) {
		super(auditService, eventService, multiTenancyRealmDao);
		setManagementService(managementService);
		setMigrationRecordDao(migrationRecordDao);
	}

	/**
	 * @param managementService the managementService to set
	 */
	public void setManagementService(IManagementService managementService) {
		this.managementService = managementService;
	}
	
	/**
	 * 
	 * @param migrationRecordDao
	 */
	public void setMigrationRecordDao(IMigrationRecordDao migrationRecordDao) {
		this.migrationRecordDao = migrationRecordDao;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.migration.IMigrationService#migrateUsersAndGroups(java.lang.String, java.util.ArrayList, java.util.ArrayList, java.lang.String)
	 */
    public List<MigrationRecord> migrateUsersAndGroups(
        String sourceRepositoryName, 
        ArrayList<MigrationUser> userList,
        ArrayList<MigrationGroup> groupList,
        String realmName) 
    throws 
        ObjectNotFoundException {
        
        List<MigrationRecord> migrationRecordsList = new ArrayList<MigrationRecord>();
        
        StringBuilder sb = new StringBuilder();
        sb.append("About to migrate users/groups from source repository: [");
        sb.append(sourceRepositoryName);
        sb.append("], number of users to migrate: ");
        sb.append(userList.size());
        sb.append(", number of groups to migrate: ");
        sb.append(groupList.size());
        logger.info(sb.toString());
        
        ServiceProvider.setIsPerformingMigration(true);
        try {
            MultiTenancyRealm multiTenancyRealm = this.getMultiTenancyRealmDao().getMultiTenancyRealmByRealmName(realmName);
            
            // Create Users.
            Iterator<MigrationUser> userIterator = userList.iterator();
            while (userIterator.hasNext()) {

                MigrationUser migrationUser = userIterator.next();
                AbstractUser securityUser = null;
                String username = migrationUser.getPrincipalName();
                String errorUsername = migrationUser.getPrincipalName();
                
                // Validate the integrity of the username.
                String errorMessage = null;
                if (migrationUser.getIsLdapUser()) {
                    errorMessage = "Unable to migrate LDAP user: " + username;
                } else {
                    errorMessage = "Unable to migrate user: " + username;
                }
                String reason = null;
                if (username.trim().equals("")) {
                    reason = IMigrationService.PRINCIPAL_NAME_CANNOT_BE_EMPTY_REASON;
                    errorUsername = DomainObject.XgetEmptyStringIdentity();
                } else if (username.startsWith(" ")) {
                    reason = IMigrationService.PRINCIPAL_NAME_HAS_LEADING_SPACES_REASON;
                } else if (username.endsWith(" ")) {
                    reason = IMigrationService.PRINCIPAL_NAME_HAS_TRAILING_SPACES_REASON;
                } else if (username.length() < multiTenancyRealm.getMinimumUsernameLength()) {
                    reason = IMigrationService.PRINCIPAL_NAME_LENGTH_TOO_SHORT_REASON;
                } else if (username.length() > DomainObject.MAX_STRING_LENGTH) {
                    reason = IMigrationService.PRINCIPAL_NAME_LENGTH_TOO_LONG_REASON;
                }
                
                if (reason != null) {
                    try {
                        MigrationRecord migrationRecord = this.migrationRecordDao.createUserMigrationRecord(
                            sourceRepositoryName, 
                            errorUsername, 
                            migrationUser.toString(),
                            reason,
                            multiTenancyRealm);
                        migrationRecordsList.add(migrationRecord);
                    } catch (ObjectAlreadyExistsException oaee) {
                        logger.error(errorMessage, oaee);
                    } catch (ValidationException ve) {
                        logger.error(errorMessage, ve);
                    }
                } else {
                    try {
                        SecurityPrincipal securityPrincipal = this.managementService.getSecurityPrincipalByPrincipalName(username, multiTenancyRealm);
                                                               
                        errorMessage = "Unable to create migration record for user: " + migrationUser;;
                        if (securityPrincipal instanceof AbstractUser) {
                            reason = IMigrationService.CANNOT_MIGRATE_USER_BECAUSE_USER_WITH_SAME_PRINCIPAL_NAME_ALREADY_EXISTS_REASON;
                        } else {
                            reason = IMigrationService.CANNOT_MIGRATE_USER_BECAUSE_GROUP_WITH_SAME_PRINCIPAL_NAME_ALREADY_EXISTS_REASON;
                        }
                        
                        try {
                            MigrationRecord migrationRecord = this.migrationRecordDao.createUserMigrationRecord(
                                    sourceRepositoryName, 
                                    username, 
                                    migrationUser.toString(),
                                    reason,
                                    multiTenancyRealm);
                            migrationRecordsList.add(migrationRecord);
                        } catch (ObjectAlreadyExistsException oaee) {
                            logger.error(errorMessage, oaee);
                        } catch (ValidationException ve) {
                            logger.error(errorMessage, ve);
                        }
                        
                    } catch (ObjectNotFoundException onfe) {

                        boolean isPasswordExpired = false;
                        String clearTextPassword = migrationUser.getClearTextPassword();
                        if (clearTextPassword == null) {
                            isPasswordExpired = true;
                            clearTextPassword = "";
                        }
                        
                        try {
                            
                            if (migrationUser.getIsLdapUser()) {
                                securityUser = this.managementService.createShadowSecurityUser(username, multiTenancyRealm);
                                logger.info("Migrated LDAP shadow security user: " + securityUser);
                            } else {
                                securityUser = this.managementService.createSecurityUser(
                                    username, 
                                    migrationUser.getFirstName(), 
                                    migrationUser.getLastName(),
                                    migrationUser.getEmailAddress(),
                                    migrationUser.getDescription(), 
                                    new ClearTextPassword(clearTextPassword),  
                                    new ClearTextPassword(clearTextPassword), 
                                    isPasswordExpired, 
                                    multiTenancyRealm);

                                if (isPasswordExpired) {
                                    logger.info("Migrated local security user: " + securityUser + " with a blank/expired password, as no password was specified.");
                                } else {
                                    logger.info("Migrated local security user: " + securityUser);
                                }
                            }
                                                    
                        } catch (ObjectAlreadyExistsException oaee) {
                            logger.error(errorMessage, oaee);
                        } catch (PasswordPolicyException ppe) {
                            logger.error(errorMessage, ppe);
                        } catch (ValidationException ve) {
                            logger.error(errorMessage, ve);
                        }
                    }
                }
                
                // See if there are any roles to associate this user to.
                String rolesToAssociateTo = migrationUser.getRolesToAssociateTo();
                if (securityUser != null && rolesToAssociateTo != null && rolesToAssociateTo.trim().length() > 0) {

                    String[] rolesToAssociateToArray = rolesToAssociateTo.split(",");
                    for (int i=0; i < rolesToAssociateToArray.length; i++) {
                        
                        String rolename = rolesToAssociateToArray[i];
                        SecurityRole securityRole = null;
                        try {
                            this.managementService.addSecurityPrincipalToSecurityRole(username, rolename, multiTenancyRealm);
                        } catch (ObjectNotFoundException onfe) {
                            logger.error("Could not associate role: " + securityRole + " with user: " + securityUser, onfe);                            
                        } catch (ValidationException ve) {
                            logger.error("Could not associate role: " + securityRole + " with user: " + securityUser, ve);
                        } catch (ObjectAlreadyExistsException oaee) {
                            logger.error("Could not associate role: " + securityRole + " with user: " + securityUser, oaee);
                        }
                    }
                }
            }
            
            
            // Create Groups.
            Iterator<MigrationGroup> groupIterator = groupList.iterator();
            while (groupIterator.hasNext()) {
                
                MigrationGroup migrationGroup = groupIterator.next();
                SecurityGroup securityGroup = null;
                String groupname = migrationGroup.getPrincipalName();
                String errorGroupname = migrationGroup.getPrincipalName();
                                
                // Validate the integrity of the groupname.
                String errorMessage = "Unable to create migration record for group: " + groupname;                
                String reason = null;
                if (groupname.trim().equals("")) {
                    reason = IMigrationService.PRINCIPAL_NAME_CANNOT_BE_EMPTY_REASON;
                    errorGroupname = DomainObject.XgetEmptyStringIdentity();
                } else if (groupname.startsWith(" ")) {
                    reason = IMigrationService.PRINCIPAL_NAME_HAS_LEADING_SPACES_REASON;
                } else if (groupname.endsWith(" ")) {
                    reason = IMigrationService.PRINCIPAL_NAME_HAS_TRAILING_SPACES_REASON;
                } else if (groupname.length() < multiTenancyRealm.getMinimumGroupnameLength()) {
                    reason = IMigrationService.PRINCIPAL_NAME_LENGTH_TOO_SHORT_REASON;
                } else if (groupname.length() > DomainObject.MAX_STRING_LENGTH) {
                    reason = IMigrationService.PRINCIPAL_NAME_LENGTH_TOO_LONG_REASON;
                }
                
                if (reason != null) {
                    try {
                        MigrationRecord migrationRecord = this.migrationRecordDao.createGroupMigrationRecord(
                            sourceRepositoryName, 
                            errorGroupname, 
                            migrationGroup.toString(),
                            reason,
                            multiTenancyRealm);
                        migrationRecordsList.add(migrationRecord);
                    } catch (ObjectAlreadyExistsException oaee) {
                        logger.error(errorMessage, oaee);
                    } catch (ValidationException ve) {
                        logger.error(errorMessage, ve);
                    }
                } else {
                    
                    try {
                        SecurityPrincipal securityPrincipal = this.managementService.getSecurityPrincipalByPrincipalName(groupname, multiTenancyRealm);
                        
                        if (securityPrincipal instanceof AbstractUser) {
                            reason = IMigrationService.CANNOT_MIGRATE_GROUP_BECAUSE_USER_WITH_SAME_PRINCIPAL_NAME_ALREADY_EXISTS_REASON;
                        } else {
                            reason = IMigrationService.CANNOT_MIGRATE_GROUP_BECAUSE_GROUP_WITH_SAME_PRINCIPAL_NAME_ALREADY_EXISTS_REASON;
                        }
                        
                        try {
                            MigrationRecord migrationRecord = this.migrationRecordDao.createGroupMigrationRecord(
                                sourceRepositoryName, 
                                groupname, 
                                migrationGroup.toString(), 
                                reason,
                                multiTenancyRealm);
                            migrationRecordsList.add(migrationRecord);
                        } catch (ObjectAlreadyExistsException oaee) {
                            logger.error(errorMessage, oaee);
                        } catch (ValidationException ve) {
                            logger.error(errorMessage, ve);
                        }
                        
                    } catch (ObjectNotFoundException onfe) {
                        
                        Set<AbstractUser> memberUsers = new TreeSet<AbstractUser>();
                        String groupMembers = migrationGroup.getMemberUsers();
                        if (groupMembers != null && groupMembers.trim().length() > 0) {
                            String[] groupMembersArray = groupMembers.split(",");
                            for (int i=0; i < groupMembersArray.length; i++) {
                                String username = groupMembersArray[i];
                                AbstractUser user;
                                try {
                                    user = this.managementService.getUserByUsername(username, multiTenancyRealm);
                                    memberUsers.add(user);
                                } catch (ObjectNotFoundException onfe2) {
                                    logger.error("Could not find user: " + username + " to add to group: " + groupname, onfe2);
                                }
                            }
                        }
                                                               
                        SecurityGroup parentGroup =  null;
                        try {
                            securityGroup = this.managementService.createSecurityGroup(
                                    groupname, 
                                    migrationGroup.getDescription(), 
                                    memberUsers, 
                                    parentGroup, 
                                    multiTenancyRealm);
                            
                            logger.info("Migrated local security group: " + securityGroup);
                            
                        } catch (ObjectAlreadyExistsException oaee) {
                            logger.error(errorMessage, oaee);
                        } catch (ValidationException ve) {
                            logger.error(errorMessage, ve);
                        } catch (ObjectNotFoundException onfe2) {
                            logger.error(errorMessage, onfe2);
                        } catch (StaleObjectException soe) {
                            logger.error(errorMessage, soe);
                        }
                    
                        // See if there are any roles to associate this group to.
                        String rolesToAssociateTo = migrationGroup.getRolesToAssociateTo();
                        if (securityGroup != null && rolesToAssociateTo != null && rolesToAssociateTo.trim().length() > 0) {
    
                            String[] rolesToAssociateToArray = rolesToAssociateTo.split(",");
                            for (int i=0; i < rolesToAssociateToArray.length; i++) {
                                
                                String rolename = rolesToAssociateToArray[i];
                                SecurityRole securityRole = null;
                                try {
                                    this.managementService.addSecurityPrincipalToSecurityRole(groupname, rolename, multiTenancyRealm);
                                } catch (ObjectNotFoundException onfe2) {
                                    logger.error("Could not associate role: " + securityRole + " with group: " + securityGroup, onfe);                            
                                } catch (ValidationException ve) {
                                    logger.error("Could not associate role: " + securityRole + " with group: " + securityGroup, ve);
                                } catch (ObjectAlreadyExistsException oaee) {
                                    logger.error("Could not associate role: " + securityRole + " with group: " + securityGroup, oaee);
                                }
                            }
                        }
                    }
                }
            }
            
            return migrationRecordsList;
        } finally {
            ServiceProvider.setIsPerformingMigration(false);
        }
	}

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.migration.IMigrationService#getSourceRepositories(java.lang.String)
     */
	public List<String> getSourceRepositories(
	    String realmName)
	throws ObjectNotFoundException {
	    
	    MultiTenancyRealm multiTenancyRealm = this.getMultiTenancyRealmDao().getMultiTenancyRealmByRealmName(realmName);
	    return this.migrationRecordDao.getMigrationRecordSourceRepositoryNames(multiTenancyRealm);
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.migration.IMigrationService#getMigrationRecords(java.lang.String, java.lang.String)
	 */
	public List<MigrationRecord> getMigrationRecords(
		String sourceRepositoryName, 
		String realmName)
    throws
        ObjectNotFoundException {
	    	    
	    MultiTenancyRealm multiTenancyRealm = this.getMultiTenancyRealmDao().getMultiTenancyRealmByRealmName(realmName);
        return this.migrationRecordDao.getAllMigrationRecordsForSourceRepository(sourceRepositoryName, multiTenancyRealm);
	}
}