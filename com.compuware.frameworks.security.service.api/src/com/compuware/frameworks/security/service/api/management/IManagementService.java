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
package com.compuware.frameworks.security.service.api.management;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.GrantedAuthority;

import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;
import com.compuware.frameworks.security.service.api.management.exception.NonDeletableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.NonModifiableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.exception.StaleObjectException;
import com.compuware.frameworks.security.service.api.model.AbstractGroup;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.PasswordPolicy;
import com.compuware.frameworks.security.service.api.model.SecurityGroup;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipal;
import com.compuware.frameworks.security.service.api.model.SecurityRole;
import com.compuware.frameworks.security.service.api.model.SecurityUser;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.SystemUser;
import com.compuware.frameworks.security.service.api.model.exception.PasswordPolicyException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * This service provides "CRUD" operations for the high-level domain objects such as Users, Groups, Roles and RoleMappings. 
 * 
 * @author tmyers
 *
 */
public interface IManagementService {
    
    // Default "low-security" password policy for the default realm (non-deletable, non-modifiable)
    /** */
    String DEFAULT_LOW_SECURITY_PASSWORD_POLICY_NAME = "low-security";
    
    /** */
    String DEFAULT_LOW_SECURITY_PASSWORD_POLICY_DESCRIPTION = "Low-security Password Policy";
        
    /** */
    int DEFAULT_LOW_SECURITY_PASSWORD_POLICY_AGE_LIMIT = -1;
    
    /** */
    int DEFAULT_LOW_SECURITY_PASSWORD_POLICY_HISTORY_LIMIT = -1;
        
    /** */
    int DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MIN_NUM_CHARS = 0;
    
    /** */
    int DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MIN_NUM_DIGITS = 0;
    
    /** */
    int DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MIN_NUM_SPECIAL_CHARS = 0;
    
    /** */
    int DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MIN_PASSWORD_LENGTH = 6;
    
    /** */
    int DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MAX_NUM_INVALID_LOGINS = -1;

    /** */
    boolean DEFAULT_LOW_SECURITY_PASSWORD_POLICY_IS_DELETABLE = false;

    /** */
    boolean DEFAULT_LOW_SECURITY_PASSWORD_POLICY_IS_MODIFIABLE = false;
    

    
    // Default "high-security" password policy for the default realm (non-deletable, non-modifiable)
    /** */
    String DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_NAME = "high-security";
    
    /** */
    String DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_DESCRIPTION = "High-security Password Policy";
    
    /** */
    int DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_AGE_LIMIT = 90; 
    
    /** */
    int DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_HISTORY_LIMIT = 6;
        
    /** */
    int DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MIN_NUM_CHARS = 3;
    
    /** */
    int DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MIN_NUM_DIGITS = 1;
    
    /** */
    int DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MIN_NUM_SPECIAL_CHARS = 0;
    
    /** */
    int DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MIN_PASSWORD_LENGTH = 8;
    
    /** */
    int DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MAX_NUM_INVALID_LOGINS = 5;
    
    /** */
    boolean DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_IS_DELETABLE = false;

    /** */
    boolean DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_IS_MODIFIABLE = false;
    
    
    
    // Default "custom" password policy for the default realm (non-deletable, modifiable)
    /** */
    String DEFAULT_CUSTOM_PASSWORD_POLICY_NAME = "custom";
    
    /** */
    String DEFAULT_CUSTOM_PASSWORD_POLICY_DESCRIPTION = "Custom Password Policy";
    
    /** */
    int DEFAULT_CUSTOM_PASSWORD_POLICY_AGE_LIMIT = 60; 
    
    /** */
    int DEFAULT_CUSTOM_PASSWORD_POLICY_HISTORY_LIMIT = 10;
        
    /** */
    int DEFAULT_CUSTOM_PASSWORD_POLICY_MIN_NUM_CHARS = 6;
    
    /** */
    int DEFAULT_CUSTOM_PASSWORD_POLICY_MIN_NUM_DIGITS = 2;
    
    /** */
    int DEFAULT_CUSTOM_PASSWORD_POLICY_MIN_NUM_SPECIAL_CHARS = 0;
    
    /** */
    int DEFAULT_CUSTOM_PASSWORD_POLICY_MIN_PASSWORD_LENGTH = 7;
    
    /** */
    int DEFAULT_CUSTOM_PASSWORD_POLICY_MAX_NUM_INVALID_LOGINS = 10;
    
    /** */
    boolean DEFAULT_CUSTOM_PASSWORD_POLICY_IS_DELETABLE = false;

    /** */
    boolean DEFAULT_CUSTOM_PASSWORD_POLICY_IS_MODIFIABLE = true;
    
    
    
    // Default realm (non-deletable, modifiable)
    /** */
    String DEFAULT_REALM_NAME = "default";
    
    /** */
    String DEFAULT_REALM_DESCRIPTION = "default realm";

    /** */
    String DEFAULT_REALM_LDAP_BASE_DN = "";

    
    // Session Management.  Eventually, these attributes will be configurable.
    /** */
    int DEFAULT_REALM_MINIMUM_USER_NAME_LENGTH = 1;
    
    /** */
    int DEFAULT_REALM_MINIMUM_GROUP_NAME_LENGTH = 1;

    /** */
    int DEFAULT_REALM_SESSION_MAX_LENGTH_IN_MINUTES = 600;

    /** */
    int DEFAULT_REALM_SESSION_TIMEOUT_IN_MINUTES = 60;
    
    /** */
    boolean DEFAULT_REALM_SESSION_ALLOW_CONCURRENT_LOGIN = true;
    
    /** */
    int DEFAULT_REALM_SESSION_MONITOR_INTERVAL_MILLIS = 5000; 
    
    /** 
     * A value of -1 means that the number of concurrent sessions is unbounded, 
     * otherwise a positive, non-zero value is expected. 
     */
    int DEFAULT_REALM_SESSION_MAX_CONCURRENT_LOGINS = -1;  
    
    /** Used for validation of permissible values. */
    public static final long MIN_SESSION_MONITOR_INTERVAL_MILLIS = 1000;

    /** Used for validation of permissible values. */
    public static final long MAX_SESSION_MONITOR_INTERVAL_MILLIS = 600000;
    
    
    /** Used for validation of permissible values. */
    public static final int MIN_INACTIVE_SESSION_TIMEOUT_MINUTES = 15;

    /** Used for validation of permissible values. */
    public static final int MAX_INACTIVE_SESSION_TIMEOUT_MINUTES = 120;
    

    /** Used for validation of permissible values. */
    public static final int MIN_SESSION_LIFE_MINUTES = 15;

    /** Used for validation of permissible values. */
    public static final int MAX_SESSION_LIFE_MINUTES = 720;
    
        
        
    /** */
    boolean DEFAULT_REALM_IS_DELETABLE = false;

    /** */
    boolean DEFAULT_REALM_IS_MODIFIABLE = true;

    /** */
    String DEFAULT_REALM_ACTIVE_PASSWORD_POLICY_NAME = DEFAULT_LOW_SECURITY_PASSWORD_POLICY_NAME;
        
        
    // Default roles  (non-deletable, modifiable)
    /** */
    boolean DEFAULT_ROLE_IS_DELETABLE = false;
    /** */
    boolean DEFAULT_ROLE_IS_MODIFIABLE = true;
    
    String   JFW_SEC_SYSTEMUSER_ROLENAME = "ROLE_JFW_SEC_SYSTEMUSER";
    String   JFW_SEC_SYSTEMUSER_DISPLAY_NAME = "CSS System User Role";
    String   JFW_SEC_SYSTEMUSER_DESCRIPTION = "Allows Security Clients to establish a secure connection with the Central Security Server.";
    boolean  JFW_SEC_SYSTEMUSER_DEFAULT = false;
    String[] JFW_SEC_SYSTEMUSER_INCLUDED_ROLES = {};

    String   JFW_SEC_MANAGEMENT_ROLENAME = "ROLE_JFW_SEC_MANAGEMENT";
    String   JFW_SEC_MANAGEMENT_DISPLAY_NAME = "CSS Management Role";
    String   JFW_SEC_MANAGEMENT_DESCRIPTION = "Allows users to perform security management operations for users, groups, roles and role assignments.";
    boolean  JFW_SEC_MANAGEMENT_DEFAULT = false;
    String[] JFW_SEC_MANAGEMENT_INCLUDED_ROLES = {};
    
    String   JFW_SEC_CONFIG_ROLENAME = "ROLE_JFW_SEC_CONFIG";
    String   JFW_SEC_CONFIG_DISPLAY_NAME = "CSS Configuration Role";
    String   JFW_SEC_CONFIG_DESCRIPTION = "Allows users to perform security configuration operations such as database connection settings, LDAP connection settings and enabling LDAP authentication.";
    boolean  JFW_SEC_CONFIG_DEFAULT = false;
    String[] JFW_SEC_CONFIG_INCLUDED_ROLES = {JFW_SEC_MANAGEMENT_ROLENAME};

    String ROLE_HIERARCHY_INCLUDES_DELIMITER = ">";

        
    // Default ACL annotations: The rights in the first pair are used for function 
    // calls returning secured objects, while the remaining read/write/delete/admin 
    // ones are used for function calls that have parameters of "secured object type".
    /** */
    String AFTER_ACL_READ = "AFTER_ACL_READ";
    
    /** */
    String AFTER_ACL_COLLECTION_READ = "AFTER_ACL_COLLECTION_READ";
    
    /** */
    String ACL_OBJECT_READ = "ACL_OBJECT_READ";
    
    /** */
    String ACL_OBJECT_WRITE = "ACL_OBJECT_WRITE";
    
    /** */
    String ACL_OBJECT_DELETE = "ACL_OBJECT_DELETE";
    
    /** */
    String ACL_OBJECT_ADMIN = "ACL_OBJECT_ADMIN";
    
    /**
     * @param databaseType (either DERBY, SQLSERVER or ORACLE)
     * @param hostname  This parameter has no meaning for DERBY
     * @param port This parameter has no meaning for DERBY
     * @param databaseName It is recommended that "cpwrSecurity" be used as the database name.
     * @param dbAuthType Can be either: LOCAL_DB_AUTH_TYPE, WINDOWS_DOMAIN_DB_AUTH_TYPE or WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE.
     *                   When the operating system is non-windows, only LOCAL_DB_AUTH_TYPE can be used. 
     *                   When WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE is used, the username and password represent the credentials for
     *                   a windows domain user specified in the <code>windowsDomain</code> parameter below.
     *                   When WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE is used, the username and password values are not used and it is
     *                   assumed that the appropriate NTML JNI driver has been installed properly.
     * @param windowsDomain This parameter only has meaning when dbAuthType is WINDOWS_DOMAIN_DB_AUTH_TYPE
     * @param username 
     * @param password
     * @param additionalConnectionStringProperties Any additional name=value pairs (delimited by a semicolon) that is appended to the end
     *                   of the JDBC connection string
     *                   
     *  @throws ValidationException                 
     */
    void testJdbcConnnection(
        String databaseType,
        String hostname,
        String port,
        String databaseName,            
        String dbAuthType,
        String windowsDomain,
        String username,
        ClearTextPassword password,
        String additionalConnectionStringProperties) 
    throws 
        ValidationException,
        InvalidCredentialsException, 
        InvalidConnectionException;           

    /**
     * Returns the default realm, which is where only one only and only one realm exists in the security repository;
     * an IllegalStateException is thrown otherwise.
     * 
     * @return MultiTenancyRealm
     */
    MultiTenancyRealm getDefaultMultiTenancyRealm();
    
    /**
     * Returns the multi-tenancy realm identified by realmName.  If realmName is null or empty <b>and</b>
     * only and only one realm exists in the security repository, then this singular realm will be returned
     * as a convenience...
     * 
     * @param realmName
     * @return MultiTenancyRealm
     * @throws ObjectNotFoundException
     */
    MultiTenancyRealm getMultiTenancyRealmByName(String realmName) throws ObjectNotFoundException;
    
    /**
     * 
     * @return The list of all multi-tenancy realms.  There <b>must</b> exist at least one 
     * (called the "default" realm).
     */
    Collection<MultiTenancyRealm> getAllMultiTenancyRealms();
    
    /**
     * It should be that a given username can exist only once in a realm, but can exist
     * in different realms (each modeling a different person/system entity for that realm)
     * 
     * @param username The realm-specific natural key for a given user (e.g. tmyers)
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return The user identified by the given username (natural key) for the given realm
     * @throws ObjectNotFoundException
     */
    AbstractUser getUserByUsername(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     * It should be that a given username can exist only once in a realm, but can exist
     * in different realms (each modeling a different person/system entity for that realm)
     * 
     * @param username The realm-specific natural key for a given user (e.g. tmyers)
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return The user identified by the given username (natural key) for the given realm
     * @throws ObjectNotFoundException
     */
    SystemUser getSystemUserByUsername(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     * It should be that a given username can exist only once in a realm, but can exist
     * in different realms (each modeling a different person/system entity for that realm)
     * 
     * @param username The realm-specific natural key for a given user (e.g. tmyers)
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return The user identified by the given username (natural key) for the given realm
     * @throws ObjectNotFoundException
     */
    SecurityUser getSecurityUserByUsername(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     * @param user
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return All security groups that the given user belongs to.
     * @throws ObjectNotFoundException
     */
    Collection<SecurityGroup> getSecurityGroupsForUser(AbstractUser user, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;  

    /**
     * This signature assumes default values of 0 and 100 for firstResult and maxResults.
     * 
     * @param firstNameCriteria
     * @param lastNameCriteria
     * @param primaryEmailAddressCriteria
     * @param isActiveCriteria
     * @param isOrQuery
     * @param multiTenancyRealm
     * @return
     * @throws ValidationException
     */
    Collection<SecurityUser> getAllSecurityUsersByCriteria(
        String firstNameCriteria,
        String lastNameCriteria,
        String primaryEmailAddressCriteria,
        Boolean isActiveCriteria,
        boolean isOrQuery,
        MultiTenancyRealm multiTenancyRealm) throws ValidationException;
    
    /**
     * Retrieves a collection of all SecurityUsers that meet the given non-null/non-empty criteria: 
     * 
     * @param firstNameCriteria 
     * @param lastNameCriteria
     * @param primaryEmailAddressCriteria
     * @param isActiveCriteria If null, then ignore this criteria; If Boolean.TRUE, only return active users; If Boolean.FALSE, only return inactive users
     * @param isOrQuery If true, the search is a logical OR query, logical AND otherwise.
     * @param firstResult The starting index into the results
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
     * [mibtdm0=[firstName=Thomas,lastName=Myers,primaryEmailAddress=thomas.myers@compuware.com]]
     * [mibsem0=[firstName=Steven,lastName=Myers,primaryEmailAddress=steven.myers@compuware.com]]
     * </pre>
     * assuming that only Thomas and Steven are the only active users with the string 'Myers' 
     * anywhere in their last name. 
     * @throws ValidationException If no search criteria are specified
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
     * @return Collection<AbstractUser>
     */
    Collection<AbstractUser> getAllUsers(MultiTenancyRealm multiTenancyRealm);  
    
    /**
     * 
     * @param username
     * @param firstName
     * @param lastName
     * @param primaryEmailAddress
     * String description
     * @param clearTextPassword
     * @param clearTextPasswordVerify
     * @param isPasswordExpired
     * @param multiTenancyRealm
     * @return The newly created user
     * @throws ObjectAlreadyExistsException
     * @throws PasswordPolicyException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityUser createSecurityUser(
       String username,
       String firstName,
       String lastName,
       String primaryEmailAddress,
       String description,
       ClearTextPassword clearTextPassword,
       ClearTextPassword clearTextPasswordVerify,
       boolean isPasswordExpired,
       MultiTenancyRealm multiTenancyRealm) 
    throws
       ObjectAlreadyExistsException,
       PasswordPolicyException,
       ValidationException;
    
   /**
    * <b>NOTES:</b> An<code>IllegalStateException</code> will be thrown if:
    * <ul>
    *   <li> If the unique identifier, <code>userName</code> is modified. 
    *   <li> If the <code>passwords</code> collection is modified, as passwords
    *   can only be associated to a user via <code>changePassword()</code> or
    *   <code>resetPassword()</code>. 
    * </ul>  
    * 
    * @param securityUser
    * @throws ObjectNotFoundException
    * @throws ValidationException
    * @throws StaleObjectException
    * @throws NonModifiableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void updateSecurityUser(SecurityUser securityUser) 
   throws 
      ObjectNotFoundException, 
      ValidationException, 
      StaleObjectException, 
      NonModifiableObjectException;

   /**
    * A user can change <b>only</b> their own password; otherwise a ServiceException will be thrown.  
    * An administrator can change anyone's password, but since the odds of them knowing the correct "old password", 
    * <code>resetPassword()</code> should be used instead.
    * 
    * @param username
    * @param currentClearTextPassword
    * @param newClearTextPassword
    * @param newClearTextPasswordVerify
    * @param multiTenancyRealm
    * @throws InvalidCredentialsException
    * @throws ObjectNotFoundException
    * @throws PasswordPolicyException
    * @throws ValidationException
    */
   void changeSecurityUserPassword(
       String username, 
       ClearTextPassword currentClearTextPassword, 
       ClearTextPassword newClearTextPassword, 
       ClearTextPassword newClearTextPasswordVerify, 
       MultiTenancyRealm multiTenancyRealm) 
   throws 
       InvalidCredentialsException, 
       ObjectNotFoundException, 
       PasswordPolicyException, 
       ValidationException; 

   /**
    * A user can change <b>only</b> their own password, see <code>changePassword()</code>. This method is to be used by 
    * Administrators.  If the administrator wishes to expire the password, they need to do this with a <code>updateSecurityUser()</code> 
    * call (in which they set 
    *    
    * @param username
    * @param newClearTextPassword
    * @param newClearTextPasswordVerify
    * @param multiTenancyRealm
    * @throws PasswordPolicyException
    * @throws ValidationException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void resetSecurityUserPassword(
       String username, 
       ClearTextPassword newClearTextPassword, 
       ClearTextPassword newClearTextPasswordVerify, 
       MultiTenancyRealm multiTenancyRealm) 
   throws 
       ObjectNotFoundException, 
       PasswordPolicyException, 
       ValidationException; 
   
   /**
    * Deletes the SecurityUser identified by <code>username</code>.
    * <p>
    * <b>NOTE:</b> A<code>ServiceException</code> will be thrown if the
    * currently authenticated user is attempting to delete their own
    * user account. It is logically implied that since this method requires
    * "admin" privileges that if there were only one admin remaining, then 
    * this admin would have to be logged in; therefore, given the above, 
    * they would not be able to delete themselves. 
    * 
    * @param username
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws NonDeletableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void deleteSecurityUser(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException;       
       
    /**
     * 
     * @param username
     * @param multiTenancyRealm
     * @return ShadowSecurityUser
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    ShadowSecurityUser createShadowSecurityUser(
       String username,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException, 
       ValidationException;
    
    /**
     * 
     * @param username
     * @param multiTenancyRealm
     * @return the given shadow object, if it exists; null otherwise.
     */
    ShadowSecurityUser getShadowSecurityUserByUsername(String username, MultiTenancyRealm multiTenancyRealm);
    
   /**
    * Deletes the ShadowSecurityUser identified by <code>username</code>.
    * 
    * @param username
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws NonDeletableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void deleteShadowSecurityUser(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException;     
    
    /**
     * 
     * @param username
     * @param description
     * @param clearTextPassword
     * @param clearTextPasswordVerify
     * @param multiTenancyRealm
     * @return SystemUser
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SystemUser createSystemUser(
       String username,
       String description,
       ClearTextPassword clearTextPassword,
       ClearTextPassword clearTextPasswordVerify,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException,
       ValidationException;

    /**
     * @param username
     * @param currentClearTextPassword
     * @param newClearTextPassword
     * @param newClearTextPasswordVerify
     * @param multiTenancyRealm
     * @throws InvalidCredentialsException
     * @throws ObjectNotFoundException
     * @throws PasswordPolicyException
     * @throws ValidationException
     * @throws NonModifiableObjectException
     */
    void changeSystemUserPassword(
        String username, 
        ClearTextPassword currentClearTextPassword, 
        ClearTextPassword newClearTextPassword, 
        ClearTextPassword newClearTextPasswordVerify, 
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        InvalidCredentialsException, 
        ObjectNotFoundException, 
        PasswordPolicyException, 
        ValidationException,
        NonModifiableObjectException; 
    
   /**
    * A <code>ServiceException</code> will be thrown if the password is changed via this method.
    * @param systemUser
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws ValidationException
    * @throws StaleObjectException
    * @throws NonModifiableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void updateSystemUser(SystemUser systemUser, MultiTenancyRealm multiTenancyRealm) 
   throws 
       ObjectNotFoundException, 
       ValidationException, 
       StaleObjectException, 
       NonModifiableObjectException; 
    
   /**
    * Deletes the SystemUser identified by <code>username</code>.
    * 
    * @param username
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws NonDeletableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void deleteSystemUser(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException;     
    
    /**
     * It should be that a given groupname can exist only once in a realm, but can exist
     * in different realms (each modeling a different group for that realm)
     * 
     * @param groupname The realm-specific natural key for a given group (e.g. admins)
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return The group identified by the given groupname (natural key) for the given realm
     * @throws ObjectNotFoundException
     */
    SecurityGroup getSecurityGroupByGroupname(String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     * 
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return All security groups for the given realm
     */
    Collection<SecurityGroup> getAllSecurityGroups(MultiTenancyRealm multiTenancyRealm);        
    
    /**
     * 
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return All groups for the given realm (security or shadow)
     */
    Collection<AbstractGroup> getAllGroups(MultiTenancyRealm multiTenancyRealm);    

    /**
     * 
     * @param groupname
     * @param description
     * @param memberUsers
     * @param parentGroup
     * @param multiTenancyRealm
     * @return SecurityGroup
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     * @throws ObjectNotFoundException
     * @throws ObjectAlreadyExistsException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityGroup createSecurityGroup( 
       String groupname,
       String description,
       Set<AbstractUser> memberUsers,
       SecurityGroup parentGroup,
       MultiTenancyRealm multiTenancyRealm) 
    throws
       ObjectAlreadyExistsException,
       ValidationException, 
       ObjectNotFoundException, 
       StaleObjectException;
    
    /**
     * 
     * @param groupname
     * @param description
     * @param assignByDefault
     * @param memberUsers
     * @param parentGroup
     * @param multiTenancyRealm
     * @return SecurityGroup
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     * @throws ObjectNotFoundException
     * @throws ObjectAlreadyExistsException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityGroup createSecurityGroup( 
       String groupname,
       String description,
       boolean assignByDefault,
       Set<AbstractUser> memberUsers,
       SecurityGroup parentGroup,
       MultiTenancyRealm multiTenancyRealm) 
    throws
       ObjectAlreadyExistsException,
       ValidationException, 
       ObjectNotFoundException, 
       StaleObjectException;
        
   /**
    * <b>NOTES:</b> An<code>IllegalStateException</code> will be thrown if:
    * <ul>
    *   <li> If the unique identifier, <code>groupName</code> is modified. 
    *   <li> If the <code>memberUsers</code> collection is modified, as users need 
    *   to added/removed via the <code>addUsersToSecurityGroup()</code>
    *   or <code>addUsersToSecurityGroup()</code> methods, respectively.
    * </ul>  
    * 
    * @param securityGroup
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws ValidationException
    * @throws StaleObjectException
    * @throws NonModifiableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void updateSecurityGroup(SecurityGroup securityGroup, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, ValidationException, StaleObjectException, NonModifiableObjectException;    
    
   /**
    * Deletes the SecurityGroup identified by <code>groupname</code>.  All
    * member users will be removed from the group first. 
    * <p>
    * <b>NOTE:</b> A<code>ServiceException</code> will be thrown if the currently 
    * authenticated user has <b>no</b> explicit user-to-role mappings associated 
    * with the admin role <b>and</b> the given group is the only group that has 
    * a group-to-role mapping that is associated with the admin role
    * 
    * @param groupname
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws NonDeletableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void deleteSecurityGroup(String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException;  
   
    /**
     * 
     * @param groupname
     * @param multiTenancyRealm
     * @return ShadowSecurityGroup
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    ShadowSecurityGroup createShadowSecurityGroup(
       String groupname,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException,
       ValidationException;
        
    /**
     * 
     * @param groupname
     * @param multiTenancyRealm
     * @return the given shadow object, if it exists; null otherwise.
     */
    ShadowSecurityGroup getShadowSecurityGroupByGroupname(String groupname, MultiTenancyRealm multiTenancyRealm);

   /**
    * 
    * @param groupname
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws NonDeletableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void deleteShadowSecurityGroup(String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException;
   
    /**
     * 
     * @param usernameList
     * @param groupname
     * @param multiTenancyRealm
     * @return the updated security group
     * @throws ObjectNotFoundException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityGroup addUsersToSecurityGroup(Collection<String> usernameList, String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     * 
     * @param usernameList
     * @param multiTenancyRealm
     * @throws ObjectNotFoundException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    void activateUsers(Collection<String> usernameList, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;
    
    /**
     * 
     * @param usernameList
     * @param multiTenancyRealm
     * @throws ObjectNotFoundException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    void deactivateUsers(Collection<String> usernameList, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     * 
     * @param groupname
     * @param multiTenancyRealm
     * @throws ObjectNotFoundException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    void activateUsersInSecurityGroup(String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;
    
    /**
     * 
     * @param groupname
     * @param multiTenancyRealm
     * @throws ObjectNotFoundException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    void deactivateUsersInSecurityGroup(String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;
    
    /**
     * Removes the given list of users from the given group.
     * <p>
     * <b>NOTE:</b> A<code>ServiceException</code> will be thrown if the 
     * currently authenticated user is trying to remove themselves from a 
     * group and that this group is the only route by which they have been
     *  granted the admin.
     *  
     * @param usernameList
     * @param groupname
     * @param multiTenancyRealm
     * @return the updated security group
     * @throws ObjectNotFoundException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityGroup removeUsersFromSecurityGroup(
        Collection<String> usernameList, 
        String groupname, 
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException;
        
    
    /**
     * It should be that a given rolename can exist only once in a realm, but can exist
     * in different realms (each modeling a different role for that realm)
     * 
     * @param rolename The realm-specific natural key for a given role (e.g. ROLE_JFW_SEC_MANAGEMENT)
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return The role identified by the given rolename (natural key) for the given realm
     * @throws ObjectNotFoundException
     */
    SecurityRole getSecurityRoleByRolename(String rolename, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     * 
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return All roles for the given realm
     */
    Collection<SecurityRole> getAllSecurityRoles(MultiTenancyRealm multiTenancyRealm);      

    /**
     * 
     * @param multiTenancyRealm
     * @return Set<String> 
     */
    Set<String> getAllSecurityRoleMappings(MultiTenancyRealm multiTenancyRealm);        

    /**
     * @param principalName
     * @param multiTenancyRealm
     * @return Set<String>
     * @throws ObjectNotFoundException 
     */
    Set<String> getAllSecurityRoleMappingsForSecurityPrincipal(String principalName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;       

    /**
     * 
     * @param rolename
     * @param displayName
     * @param description
     * @param multiTenancyRealm
     * @return SecurityRole
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityRole createSecurityRole( 
       String rolename,
       String displayName,
       String description,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException,
       ValidationException;
    
    /**
     * 
     * @param rolename
     * @param displayName
     * @param description
     * @param assignByDefault
     * @param multiTenancyRealm
     * @return SecurityRole
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityRole createSecurityRole( 
       String rolename,
       String displayName,
       String description,
       boolean assignByDefault,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException,
       ValidationException;

    /**
     * 
     * @param rolename
     * @param displayName
     * @param description
     * @param assignByDefault
     * @param includedRoles
     * @param multiTenancyRealm
     * @return SecurityRole
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityRole createSecurityRole( 
       String rolename,
       String displayName,
       String description,
       Set<SecurityRole> includedRoles,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException,
       ValidationException;

    /**
     * 
     * @param rolename
     * @param displayName
     * @param description
     * @param assignByDefault
     * @param includedRoles
     * @param multiTenancyRealm
     * @return SecurityRole
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityRole createSecurityRole( 
       String rolename,
       String displayName,
       String description,
       boolean assignByDefault,
       Set<SecurityRole> includedRoles,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException,
       ValidationException;
    
    /**
     * 
     * @param username
     * @param multiTenancyRealm
     * @return Collection<SecurityRole>
     * @throws ObjectNotFoundException
     */
    Collection<SecurityRole> getAllSecurityRolesForUser(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;       

    /**
     * 
     * @param groupname
     * @param multiTenancyRealm
     * @return Collection<SecurityRole>
     * @throws ObjectNotFoundException
     */
    Collection<SecurityRole> getAllSecurityRolesForGroup(String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;     

    /**
     * 
     * @param principalName
     * @param multiTenancyRealm
     * @return Collection<SecurityRole>
     * @throws ObjectNotFoundException
     */
    Collection<SecurityRole> getAllSecurityRolesForSecurityPrincipal(String principalName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     *
     * @param roleName The Security Role to retrieve associated SecurityPrincipals for.
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return All SecurityPrincipals associated with the given SecurityRole.  
     * These SecurityPrincipals can either be instances of AbstractUser (SecurityUser, SystemUser or ShadowSecurityUser) 
     * or AbstractGroup(SecurityGroup or ShadowSecurityGroup)
     * @throws ObjectNotFoundException If no SecurityRole named <code>securityRoleName</code> exists in the given realm. 
     */
    Collection<SecurityPrincipal> getAllSecurityPrincipalsForSecurityRole(String roleName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException;

    /**
     * 
     * @param principalNameList
     * @param roleName
     * @param multiTenancyRealm
     * @return The updated SecurityRole
     * @throws ObjectNotFoundException
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityRole addSecurityPrincipalsToSecurityRole( 
       Collection<String> principalNameList,
       String roleName,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectNotFoundException,
       ObjectAlreadyExistsException, 
       ValidationException;
    
    /**
     * 
     * @param principalName
     * @param roleName
     * @param multiTenancyRealm
     * @return The updated SecurityRole
     * @throws ObjectNotFoundException
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityRole addSecurityPrincipalToSecurityRole( 
       String principalName,
       String roleName,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectNotFoundException,
       ObjectAlreadyExistsException, 
       ValidationException;
    
    /**
     * Removes the security principal from the security role.   
     * either be a User (specifically, an AbstractUser with concrete subclasses
     * for SecurityUser, ShadowSecurityUser or SystemUser), or a SecurityGroup 
     * (who has ShadowSecurityUser as a subclass).
     * <p>
     * <b>NOTE:</b> A<code>ServiceException</code> will be thrown if the 
     * currently authenticated user is attempting to delete a security role 
     * mapping that maps themselves to the admin role <b>and</b> that mapping
     * is the only route by which they have been granted the admin role <b>or</b>
     * if they are attempting to delete a security role mapping that maps 
     * a group that the user is a member of, to the admin role <b>and</b> that 
     * mapping is the only route by which they have been granted the admin role.
     * 
     * @param principalName
     * @param roleName
     * @param multiTenancyRealm
     * @return The updated SecurityRole
     * @throws ObjectNotFoundException
     * @throws ValidationException
     * @throws 
     */
    @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
    SecurityRole removeSecurityPrincipalFromSecurityRole( 
       String principalName,
       String roleName,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectNotFoundException,
       ValidationException;

   /**
    * @param securityRole
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws ValidationException
    * @throws StaleObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void updateSecurityRole(SecurityRole securityRole, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, ValidationException, StaleObjectException, NonModifiableObjectException;   
    
   /**
    * Deletes the SecurityRole identified by <code>rolename</code>. All
    * user-to-role mappings and group-to-role mappings associated with this
    * role will be deleted first.   
    * <p>
    * <b>NOTE:</b> A<code>ServiceException</code> will be thrown if the
    * currently authenticated user is member of a group that has a group-to-role
    * mapping associated with this role <b>or</b> has an explicit user-to-role
    * mapping associated with this role.  Put another way, the role defined by the 
    * constant <code>IManagementService.JFW_SEC_MANAGEMENT_ROLENAME</code>
    * cannot be deleted, as doing so would remove privileges to invoke any mutable 
    * operations.
    * 
    * @param rolename
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws NonDeletableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void deleteSecurityRole(String rolename, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException;
      
   /**
    * @param multiTenancyRealm
    */
   void loadRoleHierarchy(MultiTenancyRealm multiTenancyRealm);

   /**
    * 
    * @throws ValidationException
    * @throws ObjectAlreadyExistsException
    * @throws PasswordPolicyException
    */
   void populateDatabase() throws ValidationException, ObjectAlreadyExistsException, PasswordPolicyException;

   /**
    * 
    * @param username
    * @param multiTenancyRealm
    * @return A collection of all <b>reachable</b> granted authorities for the given user (of any concrete class).
    * @throws ObjectNotFoundException
    */
   Collection<GrantedAuthority> getAllReachableAuthoritiesForUser(
       String username, 
       MultiTenancyRealm multiTenancyRealm) 
   throws 
       ObjectNotFoundException;
   
   /**
    * 
    * @param clearTextPassword
    * @param systemUser
    * @return <code>true</code> if the given password is correct, <code>false</code> otherwise.
    * @throws ValidationException
    */
   boolean authenticateSystemUser(String clearTextPassword, SystemUser systemUser) throws ValidationException;
   
   /**
    * 
    * @param clearTextPassword
    * @param securityUser
    * @return <code>true</code> if the given password is correct, <code>false</code> otherwise.
    * @throws ValidationException
    */
   boolean authenticateSecurityUser(String clearTextPassword, SecurityUser securityUser) throws ValidationException;
   
   /**
    * Creates a realm in an inter-mediary state with no password policies (as the method to create a 
    * password policy requires a pre-existing realm)
    * 
    * @param realmName
    * @param description
    * @param ldapBaseDn
    * @return
    * @throws ObjectAlreadyExistsException
    * @throws ValidationException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   MultiTenancyRealm createMultiTenancyRealm(
       String realmName,
       String description,
       String ldapBaseDn)
   throws
       ObjectAlreadyExistsException,
       ValidationException;
   
   /**
    * <b>NOTES:</b> An<code>IllegalStateException</code> will be thrown if:
    * <ul>
    *   <li> If the unique identifier, <code>realmName</code> is modified. 
    *   <li> If the <code>passwordPolicies</code> collection is modified, 
    *   as password policies can only be associated to a realm via 
    *   <code>addPasswordPolicyToMultiTenancyRealm()</code>. 
    * </ul>  
    * 
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws ValidationException
    * @throws StaleObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void updateMultiTenancyRealm(MultiTenancyRealm multiTenancyRealm) 
   throws 
      ObjectNotFoundException, 
      ValidationException, 
      StaleObjectException,
      NonModifiableObjectException;

   /**
    * 
    * @param realmName
    * @throws ObjectNotFoundException
    * @throws NonDeletableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void deleteMultiTenancyRealm(String realmName) throws ObjectNotFoundException, NonDeletableObjectException; 
   
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
    * @param multiTenancyRealm
    * @return
    * @throws ObjectAlreadyExistsException
    * @throws ValidationException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
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
       MultiTenancyRealm multiTenancyRealm) 
   throws
       ObjectAlreadyExistsException,
       ValidationException;
   
   /**
    * 
    * @param passwordPolicyName
    * @param realmName
    * @param description
    * @param ageLimit
    * @param historyLimit
    * @param minNumberOfDigits
    * @param minNumberOfChars
    * @param minNumberOfSpecialChars
    * @param minPasswordLength
    * @param maxNumberUnsuccessfulLoginAttempts
    * @return
    * @throws ObjectNotFoundException
    * @throws ValidationException
    * @throws StaleObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   PasswordPolicy updatePasswordPolicy(
       String passwordPolicyName,
       String realmName,
       String description,
       int ageLimit,
       int historyLimit,
       int minNumberOfDigits,
       int minNumberOfChars,
       int minNumberOfSpecialChars,
       int minPasswordLength,
       int maxNumberUnsuccessfulLoginAttempts) 
   throws 
       ObjectNotFoundException, 
       ValidationException,
       StaleObjectException,
       NonModifiableObjectException;

   /**
    * 
    * @param passwordPolicyName
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws ValidationException
    * @throws StaleObjectException
    * @throws NonModifiableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void setActivePasswordPolicy(
       String passwordPolicyName,
       MultiTenancyRealm multiTenancyRealm)
   throws 
       ObjectNotFoundException,
       ValidationException,
       StaleObjectException,
       NonModifiableObjectException;
   
   /**
    * 
    * @param passwordPolicyName
    * @param multiTenancyRealm
    * @throws ObjectNotFoundException
    * @throws ValidationException If the given password policy was the last remaining
    * password policy in the realm or if the given password policy was marked as 'active'.
    * @throws ObjectNotFoundException
    * @throws ValidationException
    * @throws StaleObjectException
    * @throws NonDeletableObjectException
    */
   @Secured({IManagementService.JFW_SEC_MANAGEMENT_ROLENAME})
   void deletePasswordPolicy(
       String passwordPolicyName,
       MultiTenancyRealm multiTenancyRealm)
   throws 
       ObjectNotFoundException,
       ValidationException,
       StaleObjectException, 
       NonDeletableObjectException;
   
   /**
    * 
    * @param groupnameCriteria
    * @param multiTenancyRealm
    * @return
    * @throws ValidationException
    */
   Collection<AbstractGroup> getAllGroupsByCriteria(
       String groupnameCriteria,
       MultiTenancyRealm multiTenancyRealm) 
   throws 
       ValidationException;

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
}