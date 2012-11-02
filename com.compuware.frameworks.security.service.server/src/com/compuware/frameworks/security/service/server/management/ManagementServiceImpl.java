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
package com.compuware.frameworks.security.service.server.management;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;

import org.apache.log4j.Logger;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.core.GrantedAuthority;

import com.compuware.frameworks.security.AbstractConfiguration;
import com.compuware.frameworks.security.CompuwareSecurityConfigurationUtil;
import com.compuware.frameworks.security.api.crypto.EncryptDecrypt;
import com.compuware.frameworks.security.persistence.PersistenceProvider;
import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao;
import com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;
import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.exception.NonDeletableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.NonModifiableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.exception.StaleObjectException;
import com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService;
import com.compuware.frameworks.security.service.api.model.AbstractGroup;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityGroupCreatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityGroupDeletedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityGroupUpdatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityMultiTenancyRealmEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityPasswordPolicyCreatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityPasswordPolicyDeletedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityPasswordPolicyUpdatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityRoleCreatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityRoleDeletedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityRoleUpdatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityUserCreatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityUserDeletedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityUserUpdatedEvent;
import com.compuware.frameworks.security.service.api.model.DomainObjectFactory;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.Password;
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
import com.compuware.frameworks.security.service.server.AbstractService;
import com.compuware.frameworks.security.service.server.ServiceProvider;
import com.compuware.frameworks.security.service.server.authentication.jdbc.JdbcAuthoritiesPopulator;
import com.compuware.frameworks.security.service.server.configuration.jdbc.JdbcConfigurationImpl;
import com.compuware.frameworks.security.service.server.crypto.CompuwareSecurityPrivateKey;

/**
 * 
 * @author tmyers
 * 
 */
public final class ManagementServiceImpl extends AbstractService implements IManagementService {
    
    /* */
    private static final String CANNOT_UPDATE_NON_PERSISTED_INSTANCE = "Cannot update a non-persisted instance of: "; 
    
    /* */
    private static final String WITH_NATURAL_IDENTITY = " with natural identity: ";
    
    /* */
    private static final String TO = " to : ";
    
    /* */
    private static final String ERROR = ", error: ";
    
    /* */
    private static final String BECAUSE_OF_VALIDATION_EXCEPTION = "] because of a validation exception, please try again.";
    
    /* */
    private static final String BECAUSE_OF_STALE_OBJECT_EXCEPTION = "] because of a stale object exception, please try again.";
    
    /* */
    private static final String GROUPNAME_CANNOT_BE_EMPTY = "Groupname cannot be null or empty.";
    
    /* */
    private static final String USERNAME_LIST_CANNOT_BE_NULL = "usernameList cannot be null.";

    /* */
    private static final String TO_ROLE = " to role: ";
    
    /* */
    private static final String FROM_ROLE = " from role: ";
    
    
    /* */
    private final Logger logger = Logger.getLogger(ManagementServiceImpl.class);
            
    /** */
    private ISecurityPrincipalDao securityPrincipalDao;

    /** */
    private ISecurityRoleDao securityRoleDao;

    /**
     * 
     * @param eventService
     * @param auditService
     * @param multiTenancyRealmDao
     * @param securityPrincipalDao
     * @param securityRoleDao
     */
    public ManagementServiceImpl(
        IEventService eventService,
        IAuditService auditService,
        IMultiTenancyRealmDao multiTenancyRealmDao,
        ISecurityPrincipalDao securityPrincipalDao,
        ISecurityRoleDao securityRoleDao) {
        super(auditService, eventService, multiTenancyRealmDao);
        setAuditService(auditService);
        setSecurityPrincipalDao(securityPrincipalDao);
        setSecurityRoleDao(securityRoleDao);        
    }
    
    /**
     * @param securityPrincipalDao the securityPrincipalDao to set
     */
    public void setSecurityPrincipalDao(ISecurityPrincipalDao securityPrincipalDao) {
        this.securityPrincipalDao = securityPrincipalDao;
    }

    /**
     * @param securityRoleDao the securityRoleDao to set
     */
    public void setSecurityRoleDao(ISecurityRoleDao securityRoleDao) {
        this.securityRoleDao = securityRoleDao;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#testJdbcConnnection(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.ClearTextPassword, java.lang.String)
     */
    public void testJdbcConnnection(
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
        InvalidConnectionException {
        
        // Get all the properties for the given database type.
        Map<String, String> map = new HashMap<String, String>();
        if (databaseType.equals(IJdbcConfiguration.SQLSERVER)) {
            map.putAll(AbstractConfiguration.DEFAULT_SQLSERVER_JDBC_PROPERTIES);
        } else if (databaseType.equals(IJdbcConfiguration.ORACLE)) {
            map.putAll(AbstractConfiguration.DEFAULT_ORACLE_JDBC_PROPERTIES);
        } else if (databaseType.equals(IJdbcConfiguration.DERBY)) {
            map.putAll(AbstractConfiguration.DEFAULT_DERBY_JDBC_PROPERTIES);
        } else {
            String reason = ValidationException.REASON_INVALID_ENUMERATED_VALUE;
            reason = reason.replace(ValidationException.TOKEN_ZERO, databaseType);
            reason = reason.replace(ValidationException.TOKEN_ONE, IJdbcConfiguration.SQLSERVER + ", " + IJdbcConfiguration.ORACLE + ", " + IJdbcConfiguration.DERBY);
            throw new ValidationException(ValidationException.FIELD_DATABASE_TYPE,  reason);
        }
        
        // Create a temporary JDBC configuration instance so that it can build the 
        // appropriate JDBC connection string and set the corresponding JDBC driver class name
        // (and deal with blanking out username/password if Windows Integrated Security).
        IJdbcConfiguration jdbcConfiguration = new JdbcConfigurationImpl(map);
        jdbcConfiguration.setJdbcConfiguration(
            databaseType, 
            hostname, 
            port, 
            databaseName, 
            dbAuthType, 
            windowsDomain, 
            username, 
            password.getClearTextPassword(), 
            additionalConnectionStringProperties);
        
        
        // Get the built connection string and derived driver class name.
        String driverClassName = jdbcConfiguration.getConfigurationValue(IJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY);
        String jdbcConnectionString = jdbcConfiguration.getConfigurationValue(IJdbcConfiguration.JDBC_CONNECTION_STRING_KEY);
        String adjustedUsername = jdbcConfiguration.getUsername();
        String adjustedPassword = jdbcConfiguration.getPassword();

        
        // Finally, test the connection.
        try {
			PersistenceProvider.getInstance().testJdbcConnection(
			    driverClassName, 
			    jdbcConnectionString, 
			    adjustedUsername, 
			    adjustedPassword);
		} catch (InterruptedException e) {
			throw new ServiceException("Unable to obtain PersistenceProvider", e);
		}
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getDefaultMultiTenancyRealm()
     */
    public MultiTenancyRealm getDefaultMultiTenancyRealm() {
        
        MultiTenancyRealm multiTenancyRealm = null;
        
        try {
            
            multiTenancyRealm = getMultiTenancyRealmByName(IManagementService.DEFAULT_REALM_NAME);
            
        } catch (ObjectNotFoundException onfe) {
            throw new ServiceException("Database initialization did not occur properly, as the default realm was not retrieved.", onfe);    
        }
        
        return multiTenancyRealm;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getMultiTenancyRealmByName(java.lang.String)
     */
    public MultiTenancyRealm getMultiTenancyRealmByName(String realmName) throws ObjectNotFoundException {
    
        return getMultiTenancyRealmDao().getMultiTenancyRealmByRealmName(realmName);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllMultiTenancyRealms()
     */
    public  Collection<MultiTenancyRealm> getAllMultiTenancyRealms() {
        
        return getMultiTenancyRealmDao().getAllMultiTenancyRealms();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getUserByUsername(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public AbstractUser getUserByUsername(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {
        
        if (username == null || username.isEmpty()) {
            throw new ServiceException("Username cannot be null or empty.");
        }
        
        return this.securityPrincipalDao.getUserByUsername(username, multiTenancyRealm);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getSystemUserByUsername(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SystemUser getSystemUserByUsername(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {
        
        if (username == null || username.isEmpty()) {
            throw new ServiceException("Username cannot be null or empty.");
        }
        
        return this.securityPrincipalDao.getSystemUserByUsername(username, multiTenancyRealm);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getSecurityUserByUsername(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityUser getSecurityUserByUsername(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {
        
        if (username == null || username.isEmpty()) {
            throw new ServiceException("Username cannot be null or empty.");
        }
        
        return this.securityPrincipalDao.getSecurityUserByUsername(username, multiTenancyRealm);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getSecurityGroupsForUser(com.compuware.frameworks.security.service.api.model.AbstractUser, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityGroup> getSecurityGroupsForUser(AbstractUser user, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {
        
        if (user == null) {
            throw new ServiceException("user cannot be null.");
        }
        
        return this.securityPrincipalDao.getSecurityGroupsForUser(user, multiTenancyRealm);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityUsersByCriteria(java.lang.String, java.lang.String, java.lang.String, boolean, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityUser> getAllSecurityUsersByCriteria(
        String firstNameCriteria,
        String lastNameCriteria,
        String primaryEmailAddressCriteria,
        Boolean isActiveCriteria,
        boolean isOrQuery,
        MultiTenancyRealm multiTenancyRealm) throws ValidationException {
        
        int firstResult = 0;
        int maxResults = 100;
        
        return this.getAllSecurityUsersByCriteria(
            firstNameCriteria, 
            lastNameCriteria, 
            primaryEmailAddressCriteria, 
            isActiveCriteria, 
            isOrQuery,
            firstResult,
            maxResults,
            multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityUsersByCriteria(java.lang.String, java.lang.String, java.lang.String, boolean, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityUser> getAllSecurityUsersByCriteria(
        String firstNameCriteria,
        String lastNameCriteria,
        String primaryEmailAddressCriteria,
        Boolean isActiveCriteria,
        boolean isOrQuery,
        int firstResult,
        int maxResults,
        MultiTenancyRealm multiTenancyRealm) throws ValidationException {
        
        return this.securityPrincipalDao.getAllSecurityUsersByCriteria(
            firstNameCriteria, 
            lastNameCriteria, 
            primaryEmailAddressCriteria, 
            isActiveCriteria, 
            isOrQuery, 
            firstResult,
            maxResults,
            multiTenancyRealm); 
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityUser> getAllSecurityUsers(MultiTenancyRealm multiTenancyRealm) {
        
        return this.securityPrincipalDao.getAllSecurityUsers(multiTenancyRealm);    
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllActiveSecurityUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityUser> getAllActiveSecurityUsers(MultiTenancyRealm multiTenancyRealm) {

        return this.securityPrincipalDao.getAllActiveSecurityUsers(multiTenancyRealm);  
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllInactiveSecurityUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityUser> getAllInactiveSecurityUsers(MultiTenancyRealm multiTenancyRealm) {

        return this.securityPrincipalDao.getAllInactiveSecurityUsers(multiTenancyRealm);    
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSystemUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SystemUser> getAllSystemUsers(MultiTenancyRealm multiTenancyRealm) {
        
        return this.securityPrincipalDao.getAllSystemUsers(multiTenancyRealm);  
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<AbstractUser> getAllUsers(MultiTenancyRealm multiTenancyRealm) {

        return this.securityPrincipalDao.getAllUsers(multiTenancyRealm);    
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createSecurityUser(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityUser createSecurityUser(
       String username,
       String firstName,
       String lastName,
       String parmPrimaryEmailAddress,
       String parmDescription,
       ClearTextPassword clearTextPassword,
       ClearTextPassword clearTextPasswordVerify,
       boolean isPasswordExpired,
       MultiTenancyRealm multiTenancyRealm) 
    throws
       ObjectAlreadyExistsException,
       PasswordPolicyException, 
       ValidationException {
        
        boolean createAuditEvent = true;
        SecurityUser securityUser = this.privateCreateSecurityUser(
            username, 
            firstName, 
            lastName, 
            parmPrimaryEmailAddress, 
            parmDescription, 
            clearTextPassword, 
            clearTextPasswordVerify, 
            isPasswordExpired, 
            createAuditEvent, 
            multiTenancyRealm);
        
        createAuditEvent(new CompuwareSecurityUserCreatedEvent(
            securityUser,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
                
        return securityUser;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#updateSecurityUser(com.compuware.frameworks.security.service.api.model.SecurityUser)
     */
   public void updateSecurityUser(SecurityUser securityUser) 
   throws 
        ObjectNotFoundException, 
        ValidationException,
        StaleObjectException,
        NonModifiableObjectException {

        if (securityUser.getPersistentIdentity() == null) {
            throw new ServiceException(CANNOT_UPDATE_NON_PERSISTED_INSTANCE 
                + securityUser.getClass().getName() 
                + WITH_NATURAL_IDENTITY 
                + securityUser.getNaturalIdentity());
        }
       
        SecurityUser oldSecurityUser = (SecurityUser)this.securityPrincipalDao.getDomainObjectById(SecurityUser.class, securityUser.getPersistentIdentity());
        if (!oldSecurityUser.getUsername().equals(securityUser.getUsername())) {
            throw new IllegalStateException("Cannot update readonly username: " + oldSecurityUser + TO + securityUser + ". To effect a username change, one must delete and then recreate the user with the desired name.");
        }   
        
        if (!oldSecurityUser.getPasswords().toString().equals(securityUser.getPasswords().toString())) {
            throw new ServiceException("Cannot update passwords: " + oldSecurityUser + " via this method.");
        }           
        this.securityPrincipalDao.evict(oldSecurityUser);
        
        this.securityPrincipalDao.update(securityUser);
        
        createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
            securityUser,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            "Updated user: [" + securityUser.getUsername() + "], new version: [" + securityUser.getVersion() + "].", 
            this.getCurrentAuthenticationContext().getRealmName()));
   }

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.management.IManagementService#changeSecurityUserPassword(java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
    */
   public void changeSecurityUserPassword(
       String username, 
       ClearTextPassword currentClearTextPassword, 
       ClearTextPassword newClearTextPassword, 
       ClearTextPassword newClearTextPasswordVerify, 
       MultiTenancyRealm multiTenancyRealm) 
   throws 
       InvalidCredentialsException, 
       ObjectNotFoundException, 
       PasswordPolicyException, 
       ValidationException {
    
       SecurityUser securityUser = getSecurityUserByUsername(username, multiTenancyRealm);
        
       String encodedPassword = new PasswordFactory().encodePassword(currentClearTextPassword);
       if (securityUser.getCurrentPassword().getEncodedPassword().equals(encodedPassword)) {
           try {
               
               boolean isPasswordExpired = false;
               Password password = this.addPasswordForSecurityUser(
                   securityUser, 
                   newClearTextPassword, 
                   newClearTextPasswordVerify,
                   isPasswordExpired);
               
               securityPrincipalDao.save(password);
               
               // Ensure that the number of invalid login attempts is zero.
               securityUser.setNumberUnsucccessfulLoginAttempts(0);
               securityPrincipalDao.save(securityUser);
               
               // TODO: TDM: We need a way of getting the originating IP Address/Hostname 
               // when there is no authentication set in the security context.
               // Like the other to-do in the authentication service, it seems that thread locals
               // need to be created for the system user and these fields.
               createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                   securityUser,
                   securityUser.getUsername(),
                   "unknown",
                   "unknown",
                   "User: [" + securityUser.getUsername() + "] changed password.",
                   securityUser.getMultiTenancyRealm().getRealmName()));
                              
           } catch (ObjectAlreadyExistsException oaee) {
               // This should not happen as we just retrieved the domain object above.
               throw new ServiceException("Could not change password for user: " + username + ERROR + oaee.getLocalizedMessage(), oaee);
           }
       } else {
           throw new InvalidCredentialsException(PasswordPolicyException.GIVEN_CURRENT_PASSWORD_IS_INCORRECT + " for user: " + username);
       }
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.management.IManagementService#resetSecurityUserPassword(java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
    */
   public void resetSecurityUserPassword(
       String username, 
       ClearTextPassword newClearTextPassword, 
       ClearTextPassword newClearTextPasswordVerify, 
       MultiTenancyRealm multiTenancyRealm) 
   throws 
       ObjectNotFoundException, 
       PasswordPolicyException, 
       ValidationException {

        SecurityUser securityUser = this.getSecurityUserByUsername(username, multiTenancyRealm);
               
        try {
            boolean isPasswordExpired = true;
            Password password = this.addPasswordForSecurityUser(
                securityUser, 
                newClearTextPassword, 
                newClearTextPasswordVerify, 
                isPasswordExpired);
            
            securityPrincipalDao.save(password);

            // Reset the user's number of unsuccessful login attempts.
            securityUser.setNumberUnsucccessfulLoginAttempts(0);
            securityPrincipalDao.save(securityUser);

            createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                    securityUser,
                    this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                    this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                    this.getCurrentAuthenticationContext().getOriginatingHostname(),
                    "Reset password for user: [" + username + "].",
                    this.getCurrentAuthenticationContext().getRealmName()));
            
        } catch (ObjectAlreadyExistsException oaee) {
            // This should not happen as we just retrieved the domain object above.
            throw new ServiceException("Could not reset password for user: " + username + ERROR + oaee.getLocalizedMessage(), oaee);
        }
   }
   
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deleteSecurityUser(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deleteSecurityUser(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException {
                
        // Get the currently authenticated user and make sure that they wouldn't be "locked out" because of this delete.
        AbstractUser securityUserToDelete = this.getUserByUsername(username, multiTenancyRealm);        
        AbstractUser currentlyAuthenticatedUser = this.getCurrentlyAuthenticatedUser();
        if (securityUserToDelete.getUsername().equals(currentlyAuthenticatedUser.getUsername())) {
            throw new ServiceException("Currently authenticated user: " + currentlyAuthenticatedUser + " cannot delete their own user account, another admin must do so.");
        }
        
        // Remove the user from any groups that they belong to.
        this.removeUserFromAllSecurityGroups(username, multiTenancyRealm);
        
        // Go ahead and delete the user. Hibernate automatically does a cascade delete of all child objects.
        try {
            
            // Remove the user from any roles that it is assigned to.
            Iterator<SecurityRole> iterator = this.securityRoleDao.getAllSecurityRolesForUser(securityUserToDelete, multiTenancyRealm).iterator();
            while (iterator.hasNext()) {
                SecurityRole securityRole = iterator.next();
                securityRole.removeMemberSecurityPrincipal(securityUserToDelete);
                this.securityRoleDao.update(securityRole);
            }
            
            this.securityPrincipalDao.delete(securityUserToDelete);
            
        } catch (NonModifiableObjectException nmoe) {
            // We should not get a non modifiable exception here because all roles are modifiable (but some are non-deletable).
            throw new ServiceException("Could not delete user: [" + securityUserToDelete + "].", nmoe);                       
        } catch (ValidationException ve) {
            // We should not get a validation exception here because all we are doing is removing a member security principal.
            throw new ServiceException("Could not delete user: [" + securityUserToDelete + BECAUSE_OF_VALIDATION_EXCEPTION, ve);                       
        } catch (StaleObjectException soe) {
            // We should not get a stale object exception here because we just retrieved it above.
            throw new ServiceException("Could not delete user: [" + securityUserToDelete + BECAUSE_OF_STALE_OBJECT_EXCEPTION, soe);
        }
        
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityUserDeletedEvent(
            securityUserToDelete,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
    }

    /*
     * 
     * @param username
     * @param multiTenancyRealm
     * @throws ObjectNotFoundException
     */
    private void removeUserFromAllSecurityGroups(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {
        
        AbstractUser user = this.getUserByUsername(username, multiTenancyRealm);
        
        Collection<String> usernameList = new HashSet<String>();
        usernameList.add(username);
        
        Collection<SecurityGroup> userGroups = this.getSecurityGroupsForUser(user, multiTenancyRealm);
        Iterator<SecurityGroup> userGroupsIterator = userGroups.iterator();
        while (userGroupsIterator.hasNext()) {
            SecurityGroup securityGroup = userGroupsIterator.next();
            String groupname = securityGroup.getGroupname();
            this.removeUsersFromSecurityGroup(usernameList, groupname, multiTenancyRealm);
        }
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getShadowSecurityUserByUsername(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public ShadowSecurityUser getShadowSecurityUserByUsername(String username, MultiTenancyRealm multiTenancyRealm) {
        
        if (username == null) {
            throw new ServiceException("Username is null");
        }
        
        return this.securityPrincipalDao.getShadowSecurityUserByUsername(username, multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deleteShadowSecurityUser(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deleteShadowSecurityUser(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException {
        
        ShadowSecurityUser shadowSecurityUserToDelete = this.securityPrincipalDao.getShadowSecurityUserByUsername(username, multiTenancyRealm);
                
        // The DAO will not throw an ObjectNotFoundException, as this getter is also used to create on-demand instances.
        if (shadowSecurityUserToDelete == null) {           
            throw new ObjectNotFoundException("Cannot find shadow user with username: [" + username + "].");
        }       
        
        // Remove the user from any groups that they belong to.
        this.removeUserFromAllSecurityGroups(username, multiTenancyRealm);

        
        // Go ahead and delete the user.
        try {
            
            // Remove the user from any roles that it is assigned to.
            Iterator<SecurityRole> iterator = this.securityRoleDao.getAllSecurityRolesForUser(shadowSecurityUserToDelete, multiTenancyRealm).iterator();
            while (iterator.hasNext()) {
                SecurityRole securityRole = iterator.next();
                securityRole.removeMemberSecurityPrincipal(shadowSecurityUserToDelete);
                this.securityRoleDao.update(securityRole);
            }
            
            this.securityPrincipalDao.delete(shadowSecurityUserToDelete);
            
        } catch (NonModifiableObjectException nmoe) {
            // We should not get a non modifiable exception here because all roles are modifiable (but some are non-deletable).
            throw new ServiceException("Could not delete shadow user: [" + shadowSecurityUserToDelete + "].", nmoe);                       
        } catch (ValidationException ve) {
            // We should not get a validation exception here because all we are doing is removing a member security principal.
            throw new ServiceException("Could not delete shadow user: [" + shadowSecurityUserToDelete + BECAUSE_OF_VALIDATION_EXCEPTION, ve);          
        } catch (StaleObjectException soe) {
            // We should not get a stale object exception here because we just retrieved it above.
            throw new ServiceException("Could not delete shadow user: [" + shadowSecurityUserToDelete + BECAUSE_OF_STALE_OBJECT_EXCEPTION, soe);
        }
        
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityUserDeletedEvent(
            shadowSecurityUserToDelete,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createSystemUser(java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SystemUser createSystemUser(
       String username,
       String description,
       ClearTextPassword clearTextPassword,
       ClearTextPassword clearTextPasswordVerify,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectAlreadyExistsException, 
        ValidationException {
        
        SystemUser systemUser = this.privateCreateSystemUser(
            username, 
            description,
            clearTextPassword,
            clearTextPasswordVerify,
            multiTenancyRealm);

        createAuditEvent(new CompuwareSecurityUserCreatedEvent(
            systemUser,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
        
        return systemUser;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#changeSystemUserPassword(java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void changeSystemUserPassword(
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
        NonModifiableObjectException {
        
        SystemUser systemUser = getSystemUserByUsername(username, multiTenancyRealm);
         
        PasswordFactory passwordFactory = new PasswordFactory();
        
        String currentEncodedPassword = passwordFactory.encodePassword(currentClearTextPassword);
        if (systemUser.getEncodedPassword().equals(currentEncodedPassword)) {
            
            Long creationDate = new Long(System.currentTimeMillis());
            boolean isPasswordExpired = false;
            
            Password newPassword = passwordFactory.createPassword(
                    newClearTextPassword, 
                    newClearTextPasswordVerify, 
                    -1, 
                    creationDate, 
                    isPasswordExpired);
            
            try {
                systemUser.setEncodedPassword(newPassword.getEncodedPassword());
                securityPrincipalDao.update(systemUser);
            } catch (StaleObjectException soe) {
                // This should not happen as we just retrieved the domain object above.
                throw new ServiceException("Could not change password for system user: " + username + ERROR + soe.getLocalizedMessage(), soe);
            }
        } else {
            throw new InvalidCredentialsException(PasswordPolicyException.GIVEN_CURRENT_PASSWORD_IS_INCORRECT + " for system user: " + username);
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#updateSystemUser(com.compuware.frameworks.security.service.api.model.SystemUser, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void updateSystemUser(SystemUser systemUser, MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException, 
        ValidationException, 
        NonModifiableObjectException {

        if (systemUser.getPersistentIdentity() == null) {
            throw new ObjectNotFoundException(CANNOT_UPDATE_NON_PERSISTED_INSTANCE 
                + systemUser.getClass().getName() 
                + WITH_NATURAL_IDENTITY 
                + systemUser.getNaturalIdentity());
        }

        SystemUser oldSystemUser = (SystemUser)this.securityPrincipalDao.getDomainObjectById(SystemUser.class, systemUser.getPersistentIdentity());
        if (!oldSystemUser.getUsername().equals(systemUser.getUsername())) {
            throw new IllegalStateException("Cannot update readonly username: " + oldSystemUser + TO + systemUser + ". To effect a username change, one must delete and then recreate the user with the desired name.");
        }
        
        if (!oldSystemUser.getEncodedPassword().equals(systemUser.getEncodedPassword())) {
            throw new ServiceException("Cannot update system user password with updateSystemUser(), use changeSystemUserPassword() instead.");
        }   
                
        try {
            this.securityPrincipalDao.evict(oldSystemUser);
            this.securityPrincipalDao.update(systemUser);
        } catch (StaleObjectException soe) {
            // We should not get a stale object exception here because we just retrieved it above.
            throw new ServiceException("Could not update system user: [" + systemUser + BECAUSE_OF_STALE_OBJECT_EXCEPTION, soe);
        }
        
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
            systemUser,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            "Updated system user: " + systemUser.getUsername() + ", new version: " + systemUser.getVersion(),
            this.getCurrentAuthenticationContext().getRealmName()));
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deleteSystemUser(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deleteSystemUser(String username, MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException,
        NonDeletableObjectException {

        // Get the currently authenticated user and make sure that they wouldn't be "locked out" because of this delete.
        AbstractUser systemUserToDelete = this.getUserByUsername(username, multiTenancyRealm);      
        AbstractUser currentlyAuthenticatedUser = this.getCurrentlyAuthenticatedUser();
        if (systemUserToDelete.getUsername().equals(currentlyAuthenticatedUser.getUsername())) {
            throw new ServiceException("Currently authenticated user: " + currentlyAuthenticatedUser + " cannot delete their own user account, another admin must do so.");
        }
        
        // Remove the user from any groups that they belong to.
        this.removeUserFromAllSecurityGroups(username, multiTenancyRealm);
                        
        // Go ahead and delete the user.
        try {
            
            // Remove the user from any roles that it is assigned to.
            Iterator<SecurityRole> iterator = this.securityRoleDao.getAllSecurityRolesForUser(systemUserToDelete, multiTenancyRealm).iterator();
            while (iterator.hasNext()) {
                SecurityRole securityRole = iterator.next();
                securityRole.removeMemberSecurityPrincipal(systemUserToDelete);
                this.securityRoleDao.update(securityRole);
            }
            
            this.securityPrincipalDao.delete(systemUserToDelete);
            
        } catch (NonModifiableObjectException nmoe) {
            // We should not get a non modifiable exception here because all roles are modifiable (but some are non-deletable).
            throw new ServiceException("Could not delete system user: [" + systemUserToDelete + "].", nmoe);                       
        } catch (ValidationException ve) {
            // We should not get a validation exception here because all we are doing is removing a member security principal.
            throw new ServiceException("Could not delete system user: [" + systemUserToDelete + BECAUSE_OF_VALIDATION_EXCEPTION, ve);                      
        } catch (StaleObjectException soe) {
            // We should not get a stale object exception here because we just retrieved it above.
            throw new ServiceException("Could not delete system user: [" + systemUserToDelete + BECAUSE_OF_STALE_OBJECT_EXCEPTION, soe);
        }
        
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityUserDeletedEvent(
            systemUserToDelete,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createShadowSecurityUser(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public ShadowSecurityUser createShadowSecurityUser(
       String username,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException,
       ValidationException {
        
        boolean createAuditEvent = true;
        ShadowSecurityUser shadowSecurityUser = this.privateCreateShadowSecurityUser(username, createAuditEvent, multiTenancyRealm);
            
        createAuditEvent(new CompuwareSecurityUserCreatedEvent(
            shadowSecurityUser,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
        
        return shadowSecurityUser;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getSecurityGroupByGroupname(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityGroup getSecurityGroupByGroupname(String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {

        if (groupname == null || groupname.isEmpty()) {
            throw new ServiceException(GROUPNAME_CANNOT_BE_EMPTY);
        }
        
        return this.securityPrincipalDao.getSecurityGroupByGroupname(groupname, multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityGroups(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityGroup> getAllSecurityGroups(MultiTenancyRealm multiTenancyRealm) {

        return this.securityPrincipalDao.getAllSecurityGroups(multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllGroups(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<AbstractGroup> getAllGroups(MultiTenancyRealm multiTenancyRealm) {

        return this.securityPrincipalDao.getAllGroups(multiTenancyRealm);   
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createSecurityGroup(java.lang.String, java.lang.String, java.util.Set, com.compuware.frameworks.security.service.api.model.SecurityGroup, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityGroup createSecurityGroup( 
        String groupname,
        String description,
        Set<AbstractUser> memberUsers,
        SecurityGroup parentGroup,
        MultiTenancyRealm multiTenancyRealm)
     throws
        ObjectAlreadyExistsException,
        ValidationException, 
        ObjectNotFoundException, 
        StaleObjectException {
        
        boolean assignByDefault = false;
        return this.createSecurityGroup(
                groupname, 
                description, 
                assignByDefault,
                memberUsers, 
                parentGroup, 
                multiTenancyRealm);
     }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createSecurityGroup(java.lang.String, java.lang.String, boolean, java.util.Set, com.compuware.frameworks.security.service.api.model.SecurityGroup, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityGroup createSecurityGroup( 
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
       StaleObjectException {
        
        boolean isDeletable = true;
        boolean isModifiable = true;
        boolean createAuditEvent = false;
        
        SecurityGroup securityGroup = privateCreateSecurityGroup(
            groupname,
            description,
            assignByDefault,
            memberUsers,
            parentGroup,
            isDeletable,
            isModifiable,
            createAuditEvent,
            multiTenancyRealm);
        
        createAuditEvent(new CompuwareSecurityGroupCreatedEvent(
                securityGroup,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                this.getCurrentAuthenticationContext().getRealmName()));
        
        return securityGroup;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#updateSecurityGroup(com.compuware.frameworks.security.service.api.model.SecurityGroup, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void updateSecurityGroup(
        SecurityGroup securityGroup, 
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException, 
        ValidationException,
        StaleObjectException,
        NonModifiableObjectException {

        if (!securityGroup.getIsModifiable()) {
            throw new NonModifiableObjectException("Cannot update a non-modifiable instance of: " 
                + securityGroup.getClass().getSimpleName() 
                + " with natural identity: " 
                + securityGroup.getNaturalIdentity());
        }
        
        if (securityGroup.getPersistentIdentity() == null) {
            throw new ObjectNotFoundException(CANNOT_UPDATE_NON_PERSISTED_INSTANCE 
                + securityGroup.getClass().getName() 
                + WITH_NATURAL_IDENTITY 
                + securityGroup.getNaturalIdentity());
        }
                
        SecurityGroup oldSecurityGroup = (SecurityGroup)this.securityPrincipalDao.getDomainObjectById(SecurityGroup.class, securityGroup.getPersistentIdentity());
        if (!oldSecurityGroup.getGroupname().equals(securityGroup.getGroupname())) {
            throw new IllegalStateException("Cannot update readonly groupname: " + oldSecurityGroup + TO + securityGroup + ". To effect a groupname change, one must delete and then recreate the group with the desired name.");
        }
        this.securityPrincipalDao.evict(oldSecurityGroup);
        
        if (!oldSecurityGroup.getMemberUsers().toString().equals(securityGroup.getMemberUsers().toString())) {
            throw new IllegalStateException("Cannot update group member users: " + securityGroup + " via this call.  Use addUsersToGroup() and removeUsersFromGroup() separately.");
        }
        
        this.securityPrincipalDao.update(securityGroup);
        
        createAuditEvent(new CompuwareSecurityGroupUpdatedEvent(
            securityGroup,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            "Updated group: [" + securityGroup.getGroupname() + "], new version: [" + securityGroup.getVersion() + "].",
            this.getCurrentAuthenticationContext().getRealmName()));
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deleteSecurityGroup(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deleteSecurityGroup(String groupname, MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException,
        NonDeletableObjectException {
                        
        SecurityGroup securityGroupToDelete = this.getSecurityGroupByGroupname(groupname, multiTenancyRealm);
        
        // TODO: TDM: Investigate this unused local.  Did I mean to do some sort of check to make sure the logged in administrator wouldn't be
        // able to remove them from a group giving them sole administrative privileges?  I thought I had done this some other way... 
        //Set<AbstractUser> memberUsers = securityGroupToDelete.getMemberUsers();
        
        // Make sure that this group is not a parent of any other group, as we require the user to delete any group hierarchy from the leaves up.
        Iterator<SecurityGroup> groupIterator = this.getAllSecurityGroups(multiTenancyRealm).iterator();
        while (groupIterator.hasNext()) {
            SecurityGroup childSecurityGroup = groupIterator.next();
            SecurityGroup parentGroup = childSecurityGroup.getParentGroup();
            if (parentGroup != null) {
                if (parentGroup.getGroupname().equals(groupname)) {
                    throw new ServiceException("Cannot delete group: " + securityGroupToDelete + " because it is a parent to: " + childSecurityGroup);
                }
            }
        }
                               
        // Go ahead and delete the group. Hibernate automatically does a cascade delete of all child objects.
        try {
            
            // Remove the user from any roles that it is assigned to.
            Iterator<SecurityRole> iterator = this.securityRoleDao.getAllSecurityRolesForGroup(securityGroupToDelete, multiTenancyRealm).iterator();
            while (iterator.hasNext()) {
                SecurityRole securityRole = iterator.next();
                securityRole.removeMemberSecurityPrincipal(securityGroupToDelete);
                this.securityRoleDao.update(securityRole);
            }
            
            this.securityPrincipalDao.delete(securityGroupToDelete);
            
            
            // Get the currently authenticated user's authorities and make sure that they wouldn't be "locked out" because of this delete.
            AbstractUser adminUser = this.getCurrentlyAuthenticatedUser();
            Collection<GrantedAuthority> newLoggedInAuthorities = this.getAllReachableAuthoritiesForUser(adminUser.getUsername(), multiTenancyRealm);
            Iterator<GrantedAuthority> newLoggedInAuthoritiesIterator = newLoggedInAuthorities.iterator();
            boolean foundManagementRole = false;
            while (newLoggedInAuthoritiesIterator.hasNext()) {
                
                GrantedAuthority authority = newLoggedInAuthoritiesIterator.next();
                if (authority.getAuthority().equalsIgnoreCase(IManagementService.JFW_SEC_MANAGEMENT_ROLENAME)) {
                    foundManagementRole = true;
                }
            }
            if (!foundManagementRole) {
                // Since ServiceException is a RuntimeException, the transaction will be rolled back by the transaction manager.
                throw new ServiceException("Cannot delete group: " 
                    + securityGroupToDelete 
                    + " because it would 'lock out' currently logged in user: " 
                    + adminUser 
                    + ".");   
            }
            
        } catch (NonModifiableObjectException nmoe) {
            // We should not get a non modifiable exception here because all roles are modifiable (but some are non-deletable).
            throw new ServiceException("Could not delete group: [" + securityGroupToDelete + "].", nmoe);                       
        } catch (ValidationException ve) {
            // We should not get a validation exception here because all we are doing is removing a member security principal.
            throw new ServiceException("Could not delete group: [" + securityGroupToDelete + BECAUSE_OF_VALIDATION_EXCEPTION, ve);                     
        } catch (StaleObjectException soe) {
            // We should not get a stale object exception here because we just retrieved it above.
            throw new ServiceException("Could not delete group: [" + securityGroupToDelete + BECAUSE_OF_STALE_OBJECT_EXCEPTION, soe);
        }
        
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityGroupDeletedEvent(
            securityGroupToDelete,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createShadowSecurityGroup(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public ShadowSecurityGroup createShadowSecurityGroup(
       String groupname,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectAlreadyExistsException, 
       ValidationException {

        ShadowSecurityGroup shadowSecurityGroup = this.securityPrincipalDao.createShadowSecurityGroup(
            groupname, 
            multiTenancyRealm);
        
        createAuditEvent(new CompuwareSecurityGroupCreatedEvent(
            shadowSecurityGroup,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
        
        return shadowSecurityGroup;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getShadowSecurityGroupByGroupname(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public ShadowSecurityGroup getShadowSecurityGroupByGroupname(String groupname, MultiTenancyRealm multiTenancyRealm) {
        return this.securityPrincipalDao.getShadowSecurityGroupByGroupname(groupname, multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deleteShadowSecurityGroup(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deleteShadowSecurityGroup(String groupname, MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException,
        NonDeletableObjectException {
        
        ShadowSecurityGroup shadowSecurityGroupToDelete = this.securityPrincipalDao.getShadowSecurityGroupByGroupname(groupname, multiTenancyRealm);
        
        // The DAO will not throw an ObjectNotFoundException, as this getter is also used to create on-demand instances.
        if (shadowSecurityGroupToDelete == null) {          
            throw new ObjectNotFoundException("Cannot find shadow group with groupname: [" + groupname + "].");
        }
                        
        // Go ahead and delete the group.
        try {
            
            // Remove the group from any roles that it is assigned to.
            Iterator<SecurityRole> iterator = this.securityRoleDao.getAllSecurityRolesForGroup(shadowSecurityGroupToDelete, multiTenancyRealm).iterator();
            while (iterator.hasNext()) {
                SecurityRole securityRole = iterator.next();
                securityRole.removeMemberSecurityPrincipal(shadowSecurityGroupToDelete);
                this.securityRoleDao.update(securityRole);
            }
            
            this.securityPrincipalDao.delete(shadowSecurityGroupToDelete);
            
        } catch (NonModifiableObjectException nmoe) {
            // We should not get a non modifiable exception here because all roles are modifiable (but some are non-deletable).
            throw new ServiceException("Could not delete shadow group: [" + shadowSecurityGroupToDelete + "].", nmoe);                       
        } catch (ValidationException ve) {
            // We should not get a validation exception here because all we are doing is removing a member security principal.
            throw new ServiceException("Could not delete shadow group: [" + shadowSecurityGroupToDelete + BECAUSE_OF_VALIDATION_EXCEPTION, ve);            
        } catch (StaleObjectException soe) {
            // We should not get a stale object exception here because we just retrieved it above.
            throw new ServiceException("Could not delete shadow group: [" + shadowSecurityGroupToDelete + BECAUSE_OF_STALE_OBJECT_EXCEPTION, soe);
        }
        
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityGroupDeletedEvent(
            shadowSecurityGroupToDelete,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#addUsersToSecurityGroup(java.util.Collection, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityGroup addUsersToSecurityGroup(
        Collection<String> usernameList, 
        String groupname, 
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException {
        
        boolean createAuditEvent = true;
        return privateAddUsersToSecurityGroup(
            usernameList, 
            groupname, 
            createAuditEvent,
            multiTenancyRealm);
    }

    /*
     * 
     * @param usernameList
     * @param groupname
     * @param createAuditEvent
     * @param multiTenancyRealm
     * @return
     * @throws ObjectNotFoundException
     */
    private SecurityGroup privateAddUsersToSecurityGroup(
        Collection<String> usernameList, 
        String groupname, 
        boolean createAuditEvent,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException {

        if (usernameList == null) {
            throw new ServiceException(USERNAME_LIST_CANNOT_BE_NULL);
        }
        
        if (groupname == null || groupname.isEmpty()) {
            throw new ServiceException(GROUPNAME_CANNOT_BE_EMPTY);
        }
        
        SecurityGroup securityGroup = this.getSecurityGroupByGroupname(groupname, multiTenancyRealm);
        
        if (usernameList.size() > 0) {
            
            Iterator<String> iterator = usernameList.iterator();
            while (iterator.hasNext()) {
                
                String username = iterator.next();
                AbstractUser user = this.getUserByUsername(username, multiTenancyRealm);
                securityGroup.getMemberUsers().add(user);
            }
                        
            try {
                this.securityPrincipalDao.save(securityGroup);
            } catch (Exception e) {
                throw new ServiceException("Could not add users: " + usernameList + " to group: " + groupname, e);
            }
            
            if (createAuditEvent) {
                createAuditEvent(new CompuwareSecurityGroupUpdatedEvent(
                    securityGroup,
                    this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                    this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                    this.getCurrentAuthenticationContext().getOriginatingHostname(),
                    "Added users: " + usernameList + " to group: [" + securityGroup.getGroupname() + "].",
                    this.getCurrentAuthenticationContext().getRealmName()));
            }
        }
        
        return securityGroup;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#activateUsers(java.util.Collection, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void activateUsers(Collection<String> usernameList, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {
        
        if (usernameList == null) {
            throw new ServiceException(USERNAME_LIST_CANNOT_BE_NULL);
        }
        
        Set<SecurityUser> securityUsers = new HashSet<SecurityUser>();
        Iterator<String> iterator = usernameList.iterator();
        while (iterator.hasNext()) {
            
            String username = iterator.next();
            SecurityUser securityUser = this.getSecurityUserByUsername(username, multiTenancyRealm);
            securityUsers.add(securityUser);
            
            createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                securityUser,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Activated user: [" + securityUser.getUsername() + "].",
                this.getCurrentAuthenticationContext().getRealmName()));
        } 
        setActivationStateForSecurityUsers(securityUsers, true);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deactivateUsers(java.util.Collection, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deactivateUsers(Collection<String> usernameList, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {
        	
    	if (usernameList == null) {
            throw new ServiceException(USERNAME_LIST_CANNOT_BE_NULL);
        }
        
        // APMOSECURITY-133 Get the currently authenticated user and make sure that they wouldn't be "locked out" because of this delete.
        AbstractUser currentlyAuthenticatedUser = this.getCurrentlyAuthenticatedUser();
        if (usernameList.contains(currentlyAuthenticatedUser.getUsername())) {
            throw new ServiceException("Currently authenticated user: " + currentlyAuthenticatedUser + " cannot deactivate their own user account, another admin must do so.");
        }
        
        Set<SecurityUser> securityUsers = new HashSet<SecurityUser>();
        
        Iterator<String> iterator = usernameList.iterator();
        while (iterator.hasNext()) {
            
            String username = iterator.next();
            SecurityUser securityUser = this.getSecurityUserByUsername(username, multiTenancyRealm);
            securityUsers.add(securityUser);
            
            createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                securityUser,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Deactivated user: [" + securityUser.getUsername() + "].",
                this.getCurrentAuthenticationContext().getRealmName()));
        } 
        setActivationStateForSecurityUsers(securityUsers, false);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#activateUsersInSecurityGroup(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void activateUsersInSecurityGroup(
        String groupname, 
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException {

        if (groupname == null || groupname.isEmpty()) {
            throw new ServiceException(GROUPNAME_CANNOT_BE_EMPTY);
        }
        
        SecurityGroup securityGroup = this.getSecurityGroupByGroupname(groupname, multiTenancyRealm);
        Set<SecurityUser> inactiveUsers = securityGroup.getInactiveSecurityUserMembers();
        setActivationStateForSecurityUsers(inactiveUsers, true);
        
        Iterator<SecurityUser> iterator = inactiveUsers.iterator();
        while (iterator.hasNext()) {
            
            SecurityUser securityUser = iterator.next();
            
            createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                securityUser,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Activated user: [" + securityUser.getUsername() + "].",
                this.getCurrentAuthenticationContext().getRealmName()));
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deactivateUsersInSecurityGroup(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deactivateUsersInSecurityGroup(
        String groupname, 
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException {

        if (groupname == null || groupname.isEmpty()) {
            throw new ServiceException(GROUPNAME_CANNOT_BE_EMPTY);
        }
        
        SecurityGroup securityGroup = this.getSecurityGroupByGroupname(groupname, multiTenancyRealm);
        Set<SecurityUser> activeUsers = securityGroup.getActiveSecurityUserMembers();
        setActivationStateForSecurityUsers(activeUsers, false);
        
        Iterator<SecurityUser> iterator = activeUsers.iterator();
        while (iterator.hasNext()) {
            
            SecurityUser securityUser = iterator.next();
            
            createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                    securityUser,
                    this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                    this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                    this.getCurrentAuthenticationContext().getOriginatingHostname(),
                    "Deactivated user: [" + securityUser.getUsername() + "].",
                    this.getCurrentAuthenticationContext().getRealmName()));
        }
    }
    
    /*
     * 
     * @param securityUsers
     * @param isActive
     * @throws ObjectNotFoundException
     */
    private void setActivationStateForSecurityUsers(
        Set<SecurityUser> securityUsers, 
        boolean isActive) 
    throws 
        ObjectNotFoundException {

        Iterator<SecurityUser> iterator = securityUsers.iterator();
        while (iterator.hasNext()) {
            
            SecurityUser securityUser = iterator.next();
            if (isActive) {
                securityUser.setIsAccountLocked(false);
            } else {
                securityUser.setIsAccountLocked(true);
            }
            
            String errorMessage = "Could not set isActive state to : " + isActive + " for user: " + securityUser;
            try {
                this.updateSecurityUser(securityUser);
            } catch (NonModifiableObjectException nmoe) {
                throw new ServiceException(errorMessage, nmoe);                       
            } catch (ValidationException ve) {
                throw new ServiceException(errorMessage, ve);
            } catch (StaleObjectException soe) {
                throw new ServiceException(errorMessage, soe);
            }
        } 
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#removeUsersFromSecurityGroup(java.util.Collection, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityGroup removeUsersFromSecurityGroup(
        Collection<String> usernameList, 
        String groupname, 
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException {

        if (usernameList == null) {
            throw new ServiceException(USERNAME_LIST_CANNOT_BE_NULL);
        }
        
        if (groupname == null || groupname.isEmpty()) {
            throw new ServiceException(GROUPNAME_CANNOT_BE_EMPTY);
        }
                
        SecurityGroup securityGroupToModify = this.getSecurityGroupByGroupname(groupname, multiTenancyRealm);
        
        // Get the currently authenticated user and make sure that they wouldn't be "locked out" because of this operation.
        AbstractUser currentlyAuthenticatedUser = this.getCurrentlyAuthenticatedUser();
        if (usernameList.contains(currentlyAuthenticatedUser.getUsername())) {
            
            // See if there are any explicit user-to-role mappings for this user to the admin role.
            boolean hasExplicitUserToAdminRoleMapping = false;
            Iterator<SecurityRole> userRoleMappingIterator = this.getAllSecurityRolesForSecurityPrincipal(currentlyAuthenticatedUser.getUsername(), multiTenancyRealm).iterator();
            while (userRoleMappingIterator.hasNext() && !hasExplicitUserToAdminRoleMapping) {
                SecurityRole roleMapping = userRoleMappingIterator.next();
                if (roleMapping.getRoleName().equals(IManagementService.JFW_SEC_MANAGEMENT_ROLENAME)) {
                    hasExplicitUserToAdminRoleMapping = true;
                }
            }
            
            // Iterate through all groups and for each group that the currently authenticated user belongs to, see if there is a group-to-role 
            // mappings associated with the admin role that is NOT the group that it is to be modified here.
            boolean hasAnotherGroupToAdminRoleMapping = false;
            Iterator<SecurityGroup>groupIterator = this.getAllSecurityGroups(multiTenancyRealm).iterator();
            while (groupIterator.hasNext() && !hasAnotherGroupToAdminRoleMapping) {
                SecurityGroup userGroup = groupIterator.next();
                if (userGroup.getMemberUsers().contains(currentlyAuthenticatedUser)) {
                    Iterator<SecurityRole> groupRoleMappingIterator = this.getAllSecurityRolesForSecurityPrincipal(userGroup.getGroupname(), multiTenancyRealm).iterator();
                    while (groupRoleMappingIterator.hasNext() && !hasAnotherGroupToAdminRoleMapping) {
                        SecurityRole roleMapping = groupRoleMappingIterator.next();
                        if (roleMapping.getRoleName().equals(IManagementService.JFW_SEC_MANAGEMENT_ROLENAME)
                            && !userGroup.getGroupname().equals(groupname)) {
                            hasAnotherGroupToAdminRoleMapping = true;
                        }
                    }
                }
            }
            
            // If the currently authenticated user has a user-to-role mapping associated with the admin role OR
            // is a member of ANOTHER group that has a group-to-role mapping associated with the admin role, THEN 
            // we can safely modify this group and not "lock out" the currently authenticated user.
            if (!hasExplicitUserToAdminRoleMapping && !hasAnotherGroupToAdminRoleMapping) {
                throw new ServiceException("Cannot modify group: " + securityGroupToModify + " because it would 'lock out' current admin: " + currentlyAuthenticatedUser + ".  hasExplicitUserToAdminRoleMapping=" + hasExplicitUserToAdminRoleMapping + ", hasAnotherGroupToAdminRoleMapping=" + hasAnotherGroupToAdminRoleMapping);   
            }
        }
        
        SecurityGroup securityGroup = this.getSecurityGroupByGroupname(groupname, multiTenancyRealm);
        
        if (usernameList.size() > 0) {
            
            Iterator<String> iterator = usernameList.iterator();
            while (iterator.hasNext()) {
                
                String username = iterator.next();
                try {
                    AbstractUser user = this.getUserByUsername(username, multiTenancyRealm);
                    securityGroup.getMemberUsers().remove(user);
                } catch (ObjectNotFoundException onfe) {
                    throw new ServiceException("Cannot remove user: " + username + " from group: " + groupname + " because it does not exist.", onfe);                
                }
                
            }
            
            try {
                this.securityPrincipalDao.save(securityGroup);
            } catch (Exception e) {
                throw new ServiceException("Could not remove: " + usernameList + " from group: " + groupname, e);
            }
            
            createAuditEvent(new CompuwareSecurityGroupUpdatedEvent(
                securityGroup,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Removed users: " + usernameList + " from group: [" + securityGroup.getGroupname() + "].",
                this.getCurrentAuthenticationContext().getRealmName()));
        }
                
        return securityGroup;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getSecurityRoleByRolename(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityRole getSecurityRoleByRolename(String rolename, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {

        if (rolename == null || rolename.isEmpty()) {
            throw new ServiceException("Rolename cannot be null or empty.");
        }
        
        return this.securityRoleDao.getSecurityRole(rolename, multiTenancyRealm);            
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityRoles(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityRole> getAllSecurityRoles(MultiTenancyRealm multiTenancyRealm) {

        return this.securityRoleDao.getAllSecurityRoles(multiTenancyRealm);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityRoleMappings(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Set<String> getAllSecurityRoleMappings(MultiTenancyRealm multiTenancyRealm) {
        
        Set<String> allSecurityRoleMappings = new TreeSet<String>();
        
        Iterator<SecurityRole> iterator = this.getAllSecurityRoles(multiTenancyRealm).iterator();
        while (iterator.hasNext()) {
            SecurityRole securityRole = iterator.next();
            allSecurityRoleMappings.addAll(securityRole.getSecurityRoleMappings());
        }
        
        return allSecurityRoleMappings;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityRoleMappingsForSecurityPrincipal(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Set<String> getAllSecurityRoleMappingsForSecurityPrincipal(String principalName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {

        Set<String> securityRoleMappings = new TreeSet<String>();
        Iterator<SecurityRole> iterator = this.getAllSecurityRoles(multiTenancyRealm).iterator();
        while (iterator.hasNext()) {
            SecurityRole securityRole = iterator.next();
            securityRoleMappings.addAll(securityRole.getSecurityRoleMappingsForSecurityPrincipal(principalName));
        }
        
        return securityRoleMappings;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createSecurityRole(java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityRole createSecurityRole( 
        String rolename,
        String displayName,
        String description,
        MultiTenancyRealm multiTenancyRealm) 
     throws 
         ObjectAlreadyExistsException, 
         ValidationException {
        
        boolean assignByDefault = false;
        return this.createSecurityRole(
            rolename, 
            displayName, 
            description, 
            assignByDefault,
            multiTenancyRealm);
     }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createSecurityRole(java.lang.String, java.lang.String, java.lang.String, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityRole createSecurityRole( 
        String rolename,
        String displayName,
        String description,
        boolean assignByDefault,
        MultiTenancyRealm multiTenancyRealm) 
     throws 
         ObjectAlreadyExistsException, 
         ValidationException {
        
        Set<SecurityRole> includedRoles = new TreeSet<SecurityRole>();
        return this.createSecurityRole(
            rolename, 
            displayName, 
            description, 
            assignByDefault,
            includedRoles,
            multiTenancyRealm);
     }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createSecurityRole(java.lang.String, java.lang.String, java.lang.String, java.util.Set, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityRole createSecurityRole( 
        String rolename,
        String displayName,
        String description,
        Set<SecurityRole> includedRoles,
        MultiTenancyRealm multiTenancyRealm) 
     throws 
         ObjectAlreadyExistsException, 
         ValidationException {
        
        boolean assignByDefault = false;
        return this.createSecurityRole(
            rolename, 
            displayName, 
            description, 
            assignByDefault,
            includedRoles,
            multiTenancyRealm);
     }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createSecurityRole(java.lang.String, java.lang.String, java.lang.String, boolean, java.util.Set, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityRole createSecurityRole( 
       String rolename,
       String displayName,
       String description,
       boolean assignByDefault,
       Set<SecurityRole> includedRoles,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectAlreadyExistsException, 
        ValidationException {

        boolean isDeletable = true;
        boolean isModifiable = true;
        
        SecurityRole securityRole = this.privateCreateSecurityRole(
            rolename, 
            displayName, 
            description, 
            assignByDefault, 
            includedRoles, 
            isDeletable, 
            isModifiable, 
            multiTenancyRealm);
            
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityRoleCreatedEvent(
                securityRole,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                this.getCurrentAuthenticationContext().getRealmName()));
        
        loadRoleHierarchy(multiTenancyRealm);
        
        return securityRole;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityRolesForUser(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityRole> getAllSecurityRolesForUser(String username, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {
    
        AbstractUser user = this.securityPrincipalDao.getUserByUsername(username, multiTenancyRealm);
        return this.securityRoleDao.getAllSecurityRolesForUser(user, multiTenancyRealm);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityRolesForGroup(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityRole> getAllSecurityRolesForGroup(String groupname, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {

        AbstractGroup group = this.securityPrincipalDao.getGroupByGroupname(groupname, multiTenancyRealm);
        return this.securityRoleDao.getAllSecurityRolesForGroup(group, multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityRolesForSecurityPrincipal(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityRole> getAllSecurityRolesForSecurityPrincipal(String principalName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {

        SecurityPrincipal securityPrincipal = this.securityPrincipalDao.getSecurityPrincipalByPrincipalName(principalName, multiTenancyRealm);
        return this.securityRoleDao.getAllSecurityRolesForSecurityPrincipal(securityPrincipal, multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllSecurityPrincipalsForSecurityRole(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<SecurityPrincipal> getAllSecurityPrincipalsForSecurityRole(String roleName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {

        SecurityRole securityRole = this.securityRoleDao.getSecurityRole(roleName, multiTenancyRealm);
        return securityRole.getMemberSecurityPrincipals();
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#addSecurityPrincipalsToSecurityRole(java.util.Collection, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityRole addSecurityPrincipalsToSecurityRole( 
        Collection<String> principalNameList,
        String roleName,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException,
        ObjectAlreadyExistsException, 
        ValidationException {
        
        boolean createAuditEvent = true;
        return privateAddSecurityPrincipalsToSecurityRole(principalNameList, roleName, createAuditEvent, multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#addSecurityPrincipalToSecurityRole(java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityRole addSecurityPrincipalToSecurityRole( 
        String principalName,
        String roleName,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException,
        ObjectAlreadyExistsException, 
        ValidationException {
        
        Collection<String> principalNameList = new ArrayList<String>();
        principalNameList.add(principalName);
        boolean createAuditEvent = true;
        return privateAddSecurityPrincipalsToSecurityRole(principalNameList, roleName, createAuditEvent, multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#removeSecurityPrincipalFromSecurityRole(java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityRole removeSecurityPrincipalFromSecurityRole( 
       String principalName,
       String roleName,
       MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectNotFoundException,
       ValidationException {
        
        SecurityPrincipal securityPrincipal = this.securityPrincipalDao.getSecurityPrincipalByPrincipalName(principalName, multiTenancyRealm);
        SecurityRole securityRole = this.securityRoleDao.getSecurityRole(roleName, multiTenancyRealm);
                    
        try {
            securityRole.removeMemberSecurityPrincipal(securityPrincipal);
            this.securityRoleDao.update(securityRole);
            
            
            // Get the currently authenticated user's authorities and make sure that they wouldn't be "locked out" because of this delete.
            AbstractUser adminUser = this.getCurrentlyAuthenticatedUser();
            Collection<GrantedAuthority> newLoggedInAuthorities = this.getAllReachableAuthoritiesForUser(adminUser.getUsername(), multiTenancyRealm);
            Iterator<GrantedAuthority> newLoggedInAuthoritiesIterator = newLoggedInAuthorities.iterator();
            boolean foundManagementRole = false;
            while (newLoggedInAuthoritiesIterator.hasNext()) {
                
                GrantedAuthority authority = newLoggedInAuthoritiesIterator.next();
                if (authority.getAuthority().equalsIgnoreCase(IManagementService.JFW_SEC_MANAGEMENT_ROLENAME)) {
                    foundManagementRole = true;
                }
            }
            if (!foundManagementRole) {
                // Since ServiceException is a RuntimeException, the transaction will be rolled back by the transaction manager.
                throw new ServiceException("Cannot disassociate securityPrincipal: " 
                    + principalName 
                    + FROM_ROLE 
                    + roleName 
                    + " because it would 'lock out' currently logged in user: " 
                    + adminUser 
                    + ".");   
            }
            
        } catch (NonModifiableObjectException nmoe) {
            // We should not get a non modifiable exception here because all roles are modifiable (but some are non-deletable).
            throw new ServiceException("Could not disassociate securityPrincipal: " + principalName + FROM_ROLE + roleName + ERROR + nmoe.getLocalizedMessage(), nmoe);                                   
        } catch (StaleObjectException soe) {
            // This should not happen as we just retrieved the domain object above.
            throw new ServiceException("Could not disassociate securityPrincipal: " + principalName + FROM_ROLE + roleName + ERROR + soe.getLocalizedMessage(), soe);
        }
                    
        if (securityPrincipal instanceof AbstractUser) {
            createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                (AbstractUser)securityPrincipal,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Disassociated user: [" + securityPrincipal + "]" + FROM_ROLE + "[" + securityRole + "].",
                this.getCurrentAuthenticationContext().getRealmName()));
        } else {
            createAuditEvent(new CompuwareSecurityGroupUpdatedEvent(
                (AbstractGroup)securityPrincipal,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Disassociated group: [" + securityPrincipal + "]" + FROM_ROLE + "[" + securityRole + "].",
                this.getCurrentAuthenticationContext().getRealmName()));
        }
        
        return securityRole;
    }
    
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.management.IManagementService#updateSecurityRole(com.compuware.frameworks.security.service.api.model.SecurityRole, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
    */
   public void updateSecurityRole(SecurityRole securityRole, MultiTenancyRealm multiTenancyRealm) 
   throws 
       ObjectNotFoundException, 
       ValidationException, 
       StaleObjectException,
       NonModifiableObjectException {
       
        if (!securityRole.getIsModifiable()) {
           throw new NonModifiableObjectException("Cannot update a non-modifiable instance of: " 
               + securityRole.getClass().getSimpleName() 
               + " with natural identity: " 
               + securityRole.getNaturalIdentity());
        }
       
        if (securityRole.getPersistentIdentity() == null) {
            throw new ObjectNotFoundException(CANNOT_UPDATE_NON_PERSISTED_INSTANCE 
                + securityRole.getClass().getName() 
                + WITH_NATURAL_IDENTITY 
                + securityRole.getNaturalIdentity());
        }
        
        SecurityRole oldSecurityRole = (SecurityRole)this.securityPrincipalDao.getDomainObjectById(SecurityRole.class, securityRole.getPersistentIdentity());
        if (!oldSecurityRole.getRoleName().equals(securityRole.getRoleName())) {
            throw new IllegalStateException("Cannot update readonly rolename: " + oldSecurityRole + TO + securityRole + ". To effect a rolename change, one must delete and then recreate the role with the desired name.");
        }
        
        if (!oldSecurityRole.getMemberSecurityPrincipals().toString().equals(securityRole.getMemberSecurityPrincipals().toString())) {
            throw new IllegalStateException("Cannot update member security principals on role: " + oldSecurityRole + " via this call.  Use addSecurityPrincipalToSecurityRole() and removeSecurityPrincipalFromSecurityRole() separately.");
        }
        
        this.securityPrincipalDao.evict(oldSecurityRole);
        
        this.securityRoleDao.update(securityRole);
        
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityRoleUpdatedEvent(
            securityRole,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            "Updated role: [" + securityRole + "], new version: [" + securityRole.getVersion() + "].", 
            this.getCurrentAuthenticationContext().getRealmName()));
        
        loadRoleHierarchy(multiTenancyRealm);
   }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deleteSecurityRole(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deleteSecurityRole(String rolename, MultiTenancyRealm multiTenancyRealm) 
    throws 
        ObjectNotFoundException,
        NonDeletableObjectException {
        
        // Get the latest version of the role.
        SecurityRole securityRoleToDelete = this.getSecurityRoleByRolename(rolename, multiTenancyRealm);
        
        // Make sure that this role is not an included role of another role. 
        Iterator<SecurityRole> roleIterator = this.getAllSecurityRoles(multiTenancyRealm).iterator();
        while (roleIterator.hasNext()) {
            SecurityRole childSecurityRole = roleIterator.next();
            Set<SecurityRole> includedRoles = childSecurityRole.getIncludedSecurityRoles();
            if (includedRoles != null) {
                if (includedRoles.contains(securityRoleToDelete)) {
                    throw new ServiceException("Cannot delete role: " + securityRoleToDelete + " because it is an included role for: " + childSecurityRole);
                }
            }
        }
        
        // Go ahead and delete the role. Hibernate automatically does a cascade delete of all child objects.
        this.securityRoleDao.delete(securityRoleToDelete);
                        
        // Create an audit event so we know who did this, when, to what and from where.
        createAuditEvent(new CompuwareSecurityRoleDeletedEvent(
            securityRoleToDelete,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
        loadRoleHierarchy(multiTenancyRealm);
    }
        
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#populateDatabase()
     */
    public void populateDatabase() throws ValidationException, ObjectAlreadyExistsException, PasswordPolicyException {
        
        logger.info("Creating canonical domain objects...");
        DomainObjectFactory domainObjectFactory = new DomainObjectFactory();
        
        
        // Create default realm (with default "low", "high" and "custom" password policies)
        MultiTenancyRealm multiTenancyRealm = domainObjectFactory.createDefaultMultiTenancyRealm();
        getMultiTenancyRealmDao().save(multiTenancyRealm);
        
        getMultiTenancyRealmDao().createPasswordPolicy(
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_NAME,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_DESCRIPTION,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_AGE_LIMIT,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_HISTORY_LIMIT,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MIN_NUM_DIGITS,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MIN_NUM_CHARS,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MIN_NUM_SPECIAL_CHARS,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MIN_PASSWORD_LENGTH,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_MAX_NUM_INVALID_LOGINS,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_IS_DELETABLE,
            IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_IS_MODIFIABLE,
            multiTenancyRealm);
                
        getMultiTenancyRealmDao().createPasswordPolicy(
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_NAME,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_DESCRIPTION,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_AGE_LIMIT,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_HISTORY_LIMIT,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MIN_NUM_DIGITS,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MIN_NUM_CHARS,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MIN_NUM_SPECIAL_CHARS,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MIN_PASSWORD_LENGTH,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_MAX_NUM_INVALID_LOGINS,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_IS_DELETABLE,
            IManagementService.DEFAULT_HIGH_SECURITY_PASSWORD_POLICY_IS_MODIFIABLE,
            multiTenancyRealm);

        getMultiTenancyRealmDao().createPasswordPolicy(
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_NAME,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_DESCRIPTION,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_AGE_LIMIT,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_HISTORY_LIMIT,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_MIN_NUM_DIGITS,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_MIN_NUM_CHARS,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_MIN_NUM_SPECIAL_CHARS,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_MIN_PASSWORD_LENGTH,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_MAX_NUM_INVALID_LOGINS,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_IS_DELETABLE,
            IManagementService.DEFAULT_CUSTOM_PASSWORD_POLICY_IS_MODIFIABLE,            
            multiTenancyRealm);
        
        // Create default roles.
        Set<SecurityRole> includedRoles = new TreeSet<SecurityRole>();
        securityRoleDao.createSecurityRole(
            IManagementService.JFW_SEC_SYSTEMUSER_ROLENAME, 
            IManagementService.JFW_SEC_SYSTEMUSER_DISPLAY_NAME,
            IManagementService.JFW_SEC_SYSTEMUSER_DESCRIPTION,            
            IManagementService.JFW_SEC_SYSTEMUSER_DEFAULT,
            includedRoles,
            IManagementService.DEFAULT_ROLE_IS_DELETABLE,
            IManagementService.DEFAULT_ROLE_IS_MODIFIABLE,            
            multiTenancyRealm);

        includedRoles = new TreeSet<SecurityRole>();
        SecurityRole jfwSecurityManagementSecurityRole = securityRoleDao.createSecurityRole(
            IManagementService.JFW_SEC_MANAGEMENT_ROLENAME, 
            IManagementService.JFW_SEC_MANAGEMENT_DISPLAY_NAME,
            IManagementService.JFW_SEC_MANAGEMENT_DESCRIPTION,            
            IManagementService.JFW_SEC_MANAGEMENT_DEFAULT,
            includedRoles,
            IManagementService.DEFAULT_ROLE_IS_DELETABLE,
            IManagementService.DEFAULT_ROLE_IS_MODIFIABLE,            
            multiTenancyRealm);

        includedRoles = new TreeSet<SecurityRole>();
        includedRoles.add(jfwSecurityManagementSecurityRole);
        securityRoleDao.createSecurityRole(
            IManagementService.JFW_SEC_CONFIG_ROLENAME, 
            IManagementService.JFW_SEC_CONFIG_DISPLAY_NAME,
            IManagementService.JFW_SEC_CONFIG_DESCRIPTION,            
            IManagementService.JFW_SEC_CONFIG_DEFAULT,
            includedRoles,
            IManagementService.DEFAULT_ROLE_IS_DELETABLE,
            IManagementService.DEFAULT_ROLE_IS_MODIFIABLE,            
            multiTenancyRealm);
        

        Properties properties = new Properties();
        File configDir = CompuwareSecurityConfigurationUtil.getCompuwareSecurityConfigurationDir();
        File file = new File(configDir.getAbsolutePath() + File.separator + "compuwareSecurityApplicationData.properties");
        InputStream inputStream = null;
        boolean needToWriteProperties = false;
        try {
            if (file.exists()) {
                logger.info("Loading custom application data properties from filesystem: " + file.getAbsolutePath());
                inputStream = new FileInputStream(file);
                properties.load(inputStream);
            }
        } catch (Exception e) {
            logger.equals("Could not load custom application data properties from file: " + file.getAbsolutePath());
        }
        
        if (inputStream == null) {
            logger.info("Loading custom application data properties from code defaults.");
                        
            try {
                ClassLoader classLoader = ManagementServiceImpl.class.getClassLoader();
                inputStream = classLoader.getResourceAsStream("/META-INF/resources/CompuwareSecurityApplicationData.properties");
                properties.load(inputStream);
            } catch (IOException ioe) {
                throw new ServiceException(ioe.getMessage(), ioe);
            }
        }
                            
        int index = 1;
        String type = "securityGroup.";
        String groupname = properties.getProperty(type + index + ".groupname");
        while (groupname != null) {
            
            logger.info("About to create canonical security group: " + groupname);
            String description = properties.getProperty(type + index + ".description");
            String strParentGroup = properties.getProperty(type + index + ".parentGroup");
            boolean assignByDefault = Boolean.parseBoolean(properties.getProperty(type + index + ".assignByDefault"));
            boolean isDeletable = Boolean.parseBoolean(properties.getProperty(type + index + ".isDeletable"));
            boolean isModifiable = Boolean.parseBoolean(properties.getProperty(type + index + ".isModifiable"));
            boolean createAuditEvent = false;
            
            SecurityGroup parentGroup = null;
            if (strParentGroup != null && strParentGroup.trim().length() > 0) {
                try {
                    parentGroup = this.getSecurityGroupByGroupname(strParentGroup.trim(), multiTenancyRealm);
                } catch (ObjectNotFoundException onfe) {
                    throw new ServiceException("Could not find parent security group: [" 
                        + strParentGroup 
                        + "] when trying to create security group: " 
                        + groupname 
                        + "].", onfe);
                }
            }
            
            try {
                Set<AbstractUser> memberUsers = new TreeSet<AbstractUser>();
                this.privateCreateSecurityGroup(
                    groupname,
                    description,
                    assignByDefault,
                    memberUsers,
                    parentGroup,
                    isDeletable,
                    isModifiable,
                    createAuditEvent,
                    multiTenancyRealm);
            } catch (ObjectNotFoundException onfe) {
                throw new ServiceException(onfe.getMessage(), onfe);
            } catch (StaleObjectException soe) {
                throw new ServiceException(soe.getMessage(), soe);
            } 
                                
            index = index + 1;
            groupname = properties.getProperty(type + index + ".groupname");
        }
        

        
        index = 1;
        type = "systemUser.";
        String username = properties.getProperty(type + index + ".username");
        while (username != null) {
            
            logger.info("About to create canonical system user: " + username);
            String clearTextPassword = properties.getProperty(type + index + ".clearTextPassword");
            if (clearTextPassword != null) {
                needToWriteProperties = true;
                properties.remove(type + index + ".clearTextPassword");
                String encryptedPassword = EncryptDecrypt.encryptText(clearTextPassword, CompuwareSecurityPrivateKey.getInstance().getKey());
                properties.setProperty(type + index + ".password", encryptedPassword);
            } else {
                String encryptedPassword = properties.getProperty(type + index + ".password");
                clearTextPassword = EncryptDecrypt.decryptText(encryptedPassword, CompuwareSecurityPrivateKey.getInstance().getKey());
            }
            String description = properties.getProperty(type + index + ".description");
            boolean isDeletable = Boolean.parseBoolean(properties.getProperty(type + index + ".isDeletable"));
            boolean isModifiable = Boolean.parseBoolean(properties.getProperty(type + index + ".isModifiable"));
            
            this.privateCreateSystemUser(
                username, 
                description,
                new ClearTextPassword(clearTextPassword),
                new ClearTextPassword(clearTextPassword),
                isDeletable,
                isModifiable,
                multiTenancyRealm);
            
            index = index + 1;
            username = properties.getProperty(type + index + ".username");
        }
        
        
        
        index = 1;
        type = "securityUser.";
        username = properties.getProperty(type + index + ".username");
        while (username != null) {
            
            logger.info("About to create canonical security user: " + username);
            String clearTextPassword = properties.getProperty(type + index + ".clearTextPassword");
            if (clearTextPassword != null) {
                needToWriteProperties = true;
                properties.remove(type + index + ".clearTextPassword");
                String encryptedPassword = EncryptDecrypt.encryptText(clearTextPassword, CompuwareSecurityPrivateKey.getInstance().getKey());
                properties.setProperty(type + index + ".password", encryptedPassword);
            } else {
                String encryptedPassword = properties.getProperty(type + index + ".password");
                clearTextPassword = EncryptDecrypt.decryptText(encryptedPassword, CompuwareSecurityPrivateKey.getInstance().getKey());
            }            
            String firstName = properties.getProperty(type + index + ".firstName");
            String lastName = properties.getProperty(type + index + ".lastName");
            String emailAddress = properties.getProperty(type + index + ".emailAddress");
            String description = properties.getProperty(type + index + ".description");
            
            boolean isPasswordExpired = false;
            boolean createAuditEvent = false;
            
            this.privateCreateSecurityUser(
                username, 
                firstName, 
                lastName, 
                emailAddress, 
                description, 
                new ClearTextPassword(clearTextPassword), 
                new ClearTextPassword(clearTextPassword), 
                isPasswordExpired, 
                createAuditEvent, 
                multiTenancyRealm);
            
            index = index + 1;
            username = properties.getProperty(type + index + ".username");
        }
        
        
        
        index = 1;
        type = "securityGroup.";
        groupname = properties.getProperty(type + index + ".groupname");
        while (groupname != null) {
                        
            String strMemberUsers = properties.getProperty(type + index + ".memberUsers");
            logger.info("About to add member users: [" + strMemberUsers + "] to canonical security group: " + groupname);
                            
            Collection<String> usernameList = new ArrayList<String>();
            if (strMemberUsers != null && strMemberUsers.trim().length() > 0) {
                StringTokenizer stringTokenizer = new StringTokenizer(strMemberUsers, ",");
                while (stringTokenizer.hasMoreTokens()) {
                    usernameList.add(stringTokenizer.nextToken());
                }
            }
            
            try {
                boolean createAuditEvent = false;
                privateAddUsersToSecurityGroup(
                    usernameList, 
                    groupname, 
                    createAuditEvent,
                    multiTenancyRealm);
            } catch (ObjectNotFoundException onfe) {
                throw new ServiceException("Could not add security users: [" 
                    + usernameList 
                    + "] to security group: " 
                    + groupname 
                    + "].", onfe);
            } 
                                
            index = index + 1;
            groupname = properties.getProperty(type + index + ".groupname");
        }
        

        
        index = 1;
        type = "securityRole.";
        String rolename = properties.getProperty(type + index + ".rolename");
        while (rolename != null) {
            
            logger.info("About to create canonical security role: " + rolename);
            String displayName = properties.getProperty(type + index + ".displayName");
            String description = properties.getProperty(type + index + ".description");
            boolean assignByDefault = Boolean.parseBoolean(properties.getProperty(type + index + ".assignByDefault"));
            String strIncludedRoles = properties.getProperty(type + index + ".includedRoles");
            String strMemberSecurityPrincipals = properties.getProperty(type + index + ".memberSecurityPrincipals");
            boolean isDeletable = Boolean.parseBoolean(properties.getProperty(type + index + ".isDeletable"));
            boolean isModifiable = Boolean.parseBoolean(properties.getProperty(type + index + ".isModifiable"));
            boolean createAuditEvent = false;
                                
            includedRoles = new TreeSet<SecurityRole>();
            if (strIncludedRoles != null && strIncludedRoles.trim().length() > 0) {
                StringTokenizer stringTokenizer = new StringTokenizer(strIncludedRoles, ",");
                while (stringTokenizer.hasMoreTokens()) {
                    String includedRolename = stringTokenizer.nextToken();
                    try {
                        includedRoles.add(this.getSecurityRoleByRolename(includedRolename, multiTenancyRealm));
                    } catch (ObjectNotFoundException onfe) {
                        throw new ServiceException("Could not find security role: [" 
                            + includedRolename 
                            + "] to add as an included role when trying to create security role: " 
                            + rolename 
                            + "].", onfe);
                    }
                }
            }

            this.privateCreateSecurityRole(
                rolename, 
                displayName, 
                description, 
                assignByDefault, 
                includedRoles, 
                isDeletable, 
                isModifiable, 
                multiTenancyRealm);
            
            if (strMemberSecurityPrincipals != null && strMemberSecurityPrincipals.trim().length() > 0) {
                Collection<String> principalNameList = new ArrayList<String>();
                StringTokenizer stringTokenizer = new StringTokenizer(strMemberSecurityPrincipals, ",");                        
                while (stringTokenizer.hasMoreTokens()) {
                    principalNameList.add(stringTokenizer.nextToken());
                }
                try {
                    logger.info("About to associate security principals: [" + principalNameList + "] to canonical security role: " + rolename);
                    this.privateAddSecurityPrincipalsToSecurityRole(
                        principalNameList, 
                        rolename, 
                        createAuditEvent, 
                        multiTenancyRealm);                                
                } catch (ObjectNotFoundException onfe) {
                    throw new ServiceException("Could not find security principal to associate with security role: " 
                        + rolename 
                        + "], error: "
                        + onfe.getMessage(), onfe);
                } 
            }
                                
            index = index + 1;
            rolename = properties.getProperty(type + index + ".rolename");
        }
        
        // See if we need to write the properties file, as we may have needed to encrypt passwords with our secret key.
        if (needToWriteProperties) {
            try {
                String comments = "Compuware Security Canonical Application Data";
                this.writeProperties(properties, comments, file);    
            } catch (IOException ioe) {
                logger.error("Unable to save file: [" + file.getAbsolutePath() + "], error: [" + ioe.getMessage() + "].", ioe);
            }
        }                         
        
        // Load the role hierarchy bean given the roles we just created above.
        loadRoleHierarchy(multiTenancyRealm);
        
        logger.info("Done creating canonical domain objects...");
    }

    /**
     * @param multiTenancyRealm 
     */
    public void loadRoleHierarchy(MultiTenancyRealm multiTenancyRealm) {
        
        StringBuilder sb = new StringBuilder();
        if (logger.isDebugEnabled()) {
            logger.debug("Loading role hierarchy for realm: " + multiTenancyRealm);    
        }
                        
        Collection<SecurityRole> allSecurityRoles = this.getAllSecurityRoles(multiTenancyRealm);
        Iterator<SecurityRole> childRoleIterator = allSecurityRoles.iterator();
        while (childRoleIterator.hasNext()) {
            
            SecurityRole childRole = childRoleIterator.next();
            Set<SecurityRole> includedRoles = childRole.getIncludedSecurityRoles();
            if (includedRoles != null && includedRoles.size() > 0) {

                Iterator<SecurityRole> parentRoleIterator = childRole.getIncludedSecurityRoles().iterator();
                while (parentRoleIterator.hasNext()) {
                    
                    SecurityRole parentRole = parentRoleIterator.next();
                    
                    sb.append(childRole.getRoleName());
                    sb.append(" ");
                    sb.append(IManagementService.ROLE_HIERARCHY_INCLUDES_DELIMITER);
                    sb.append(" ");
                    sb.append(parentRole.getRoleName());
                    sb.append(" ");
                }            
            }
        }
        
        String roleHierarchyStringRepresentation = sb.toString();
        if (roleHierarchyStringRepresentation.isEmpty()) {
            
            logger.error("No security roles were found for realm, using defaults: " + multiTenancyRealm);
            sb.append(IManagementService.JFW_SEC_CONFIG_ROLENAME);
            sb.append(" ");
            sb.append(IManagementService.ROLE_HIERARCHY_INCLUDES_DELIMITER);
            sb.append(" ");
            sb.append(IManagementService.JFW_SEC_MANAGEMENT_ROLENAME);
            sb.append(" ");
            roleHierarchyStringRepresentation = sb.toString();
        }        
        
        // TODO: TDM: Change this from singleton scope to per-call so the hierarchy can be realm-specific.
        RoleHierarchyImpl roleHierarchyImpl = ServiceProvider.getInstance().getRoleHierarchyImpl();
        roleHierarchyImpl.setHierarchy(roleHierarchyStringRepresentation); 
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllReachableAuthoritiesForUser(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<GrantedAuthority> getAllReachableAuthoritiesForUser(
            String username, 
            MultiTenancyRealm multiTenancyRealm) 
        throws 
            ObjectNotFoundException {
        
        AbstractUser abstractUser = this.getUserByUsername(username, multiTenancyRealm);
        
        Collection<String> userLdapGroups = null;
        if (abstractUser instanceof ShadowSecurityUser) {
            
            ILdapSearchService ldapSearchService = ServiceProvider.getInstance().getLdapSearchService();
            try {
                ShadowSecurityUser shadowSecurityUser = ldapSearchService.getLdapUser(username, multiTenancyRealm);
                userLdapGroups = ldapSearchService.getLdapGroupsForLdapUserDn(shadowSecurityUser.getShadowedUserLdapDN(), multiTenancyRealm);
            } catch (Exception e) {
                throw new ServiceException("Could not retrieve LDAP groups for LDAP user: " + abstractUser + ERROR + e.getMessage(), e);
            }
        }
        
        JdbcAuthoritiesPopulator jdbcAuthoritiesPopulator = new JdbcAuthoritiesPopulator(this);
        return jdbcAuthoritiesPopulator.getGrantedAuthorities(abstractUser, userLdapGroups);
    }

    /**
     * 
     * @param username
     * @param description
     * @param clearTextPassword
     * @param clearTextPasswordVerify
     * @param multiTenancyRealm
     * @return
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    private SystemUser privateCreateSystemUser(
        String username,
        String description,
        ClearTextPassword clearTextPassword,
        ClearTextPassword clearTextPasswordVerify,
        MultiTenancyRealm multiTenancyRealm) 
     throws 
         ObjectAlreadyExistsException, 
         ValidationException {

        boolean isDeletable = true;
        boolean isModifiable = true;
        return privateCreateSystemUser(
            username,
            description,
            clearTextPassword,
            clearTextPasswordVerify,
            isDeletable,
            isModifiable,
            multiTenancyRealm); 
    }   
    
    /**
     * 
     * @param username
     * @param description
     * @param clearTextPassword
     * @param clearTextPasswordVerify
     * @param isDeletable
     * @param isModifiable
     * @param multiTenancyRealm
     * @return
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    private SystemUser privateCreateSystemUser(
        String username,
        String description,
        ClearTextPassword clearTextPassword,
        ClearTextPassword clearTextPasswordVerify,
        boolean isDeletable,
        boolean isModifiable,
        MultiTenancyRealm multiTenancyRealm) 
     throws 
         ObjectAlreadyExistsException, 
         ValidationException {
        
         if (!clearTextPassword.equals(clearTextPasswordVerify)) {
            throw new ValidationException(ValidationException.FIELD_PASSWORD_VERIFY, ValidationException.REASON_PASSWORD_VERIFY_DOES_NOT_MATCH_PASSWORD);
         }
                 
         String encodedPassword = new PasswordFactory().encodePassword(clearTextPassword);
         SystemUser systemUser = new DomainObjectFactory().createSystemUser(
             username, 
             description,
             encodedPassword,
             isDeletable,
             isModifiable,
             multiTenancyRealm);
         
         systemUser = this.securityPrincipalDao.createSystemUser(systemUser);
         
         try {
             SecurityRole systemUserRole = this.securityRoleDao.getSecurityRole(IManagementService.JFW_SEC_SYSTEMUSER_ROLENAME, multiTenancyRealm);
             systemUserRole.addMemberSecurityPrincipal(systemUser);
             this.securityRoleDao.update(systemUserRole);
         } catch (NonModifiableObjectException nmoe) {
             // We should not get a non modifiable exception here because all roles are modifiable (but some are non-deletable).
             throw new ServiceException("Could not update system user role.", nmoe);                       
         } catch (StaleObjectException soe) {
             throw new ServiceException("Could not update system user role.", soe);
         } catch (ObjectNotFoundException onfe) {
             throw new ServiceException("Could not find system user role.", onfe);
         }
                                
         return systemUser;
     }
    
    /*
     * 
     * @param username
     * @param firstName
     * @param lastName
     * @param parmPrimaryEmailAddress
     * @param parmDescription
     * @param clearTextPassword
     * @param clearTextPasswordVerify
     * @param isPasswordExpired
     * @param createAuditEvent
     * @param multiTenancyRealm
     * @return
     * @throws ObjectAlreadyExistsException
     * @throws PasswordPolicyException
     * @throws ValidationException
     */
    private SecurityUser privateCreateSecurityUser(
        String username,
        String firstName,
        String lastName,
        String parmPrimaryEmailAddress,
        String parmDescription,
        ClearTextPassword clearTextPassword,
        ClearTextPassword clearTextPasswordVerify,
        boolean isPasswordExpired,
        boolean createAuditEvent,
        MultiTenancyRealm multiTenancyRealm) 
     throws
        ObjectAlreadyExistsException,
        PasswordPolicyException, 
        ValidationException {
             
         String primaryEmailAddress = parmPrimaryEmailAddress;
         if (primaryEmailAddress == null) {
             primaryEmailAddress = "";
         }
         
         String description = parmDescription;
         if (description == null) {
             description = "";
         }
         
         SecurityUser securityUser = new DomainObjectFactory().createSecurityUserWithoutPassword(
             username, 
             firstName, 
             lastName,
             primaryEmailAddress,
             description, 
             multiTenancyRealm);

         this.addPasswordForSecurityUser(
             securityUser, 
             clearTextPassword, 
             clearTextPasswordVerify, 
             isPasswordExpired);
                 
         securityUser = this.securityPrincipalDao.createSecurityUser(securityUser);
                 
         assignDefaultGroups(securityUser, createAuditEvent);
         assignDefaultRoles(securityUser, createAuditEvent);
                 
         return securityUser;
     }
 
    /*
     * 
     * @param username
     * @param createAuditEvent
     * @param multiTenancyRealm
     * @return
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    private ShadowSecurityUser privateCreateShadowSecurityUser(
        String username,
        boolean createAuditEvent,
        MultiTenancyRealm multiTenancyRealm) 
     throws 
        ObjectAlreadyExistsException,
        ValidationException {
         
         ShadowSecurityUser shadowSecurityUser = this.securityPrincipalDao.createShadowSecurityUser(
             username, 
             multiTenancyRealm);
             
         assignDefaultGroups(shadowSecurityUser, createAuditEvent);
         assignDefaultRoles(shadowSecurityUser, createAuditEvent);
         
         return shadowSecurityUser;
     }
    
    /*
     * 
     * @param abstractUser
     * @param createAuditEvent
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    private void assignDefaultGroups(AbstractUser abstractUser, boolean createAuditEvent) throws ObjectAlreadyExistsException, ValidationException {
        
        MultiTenancyRealm multiTenancyRealm = abstractUser.getMultiTenancyRealm();
        Collection<SecurityGroup> defaultSecurityGroups = this.securityPrincipalDao.getAllDefaultSecurityGroups(multiTenancyRealm);
        Iterator<SecurityGroup> defaultSecurityGroupsIterator = defaultSecurityGroups.iterator();
        boolean assignedAtLeastOne = false;
        while (defaultSecurityGroupsIterator.hasNext()) {
            SecurityGroup securityGroup = defaultSecurityGroupsIterator.next();
            securityGroup.addUser(abstractUser);
            this.securityPrincipalDao.save(securityGroup);
            if (!assignedAtLeastOne) {
                assignedAtLeastOne = true;
            }
        }
        if (createAuditEvent && assignedAtLeastOne) {
            createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                abstractUser,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Assigned default groups: " + defaultSecurityGroups + " to user: [" + abstractUser + "].",
                this.getCurrentAuthenticationContext().getRealmName()));
        }
    }

    /*
     * 
     * @param abstractUser
     * @param createAuditEvent
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    private void assignDefaultRoles(AbstractUser abstractUser, boolean createAuditEvent) throws ObjectAlreadyExistsException, ValidationException {
        
        MultiTenancyRealm multiTenancyRealm = abstractUser.getMultiTenancyRealm();
        Collection<SecurityRole> defaultSecurityRoles = this.securityRoleDao.getAllDefaultSecurityRoles(multiTenancyRealm);
        Iterator<SecurityRole> defaultSecurityRolesIterator = defaultSecurityRoles.iterator();
        boolean assignedAtLeastOne = false;
        while (defaultSecurityRolesIterator.hasNext()) {
            SecurityRole securityRole = defaultSecurityRolesIterator.next();
            securityRole.addMemberSecurityPrincipal(abstractUser);
            this.securityRoleDao.save(securityRole);
            if (!assignedAtLeastOne) {
                assignedAtLeastOne = true;
            }
        }
        if (createAuditEvent && assignedAtLeastOne) {
            createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                abstractUser,
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Assigned default roles: " + defaultSecurityRoles,
                this.getCurrentAuthenticationContext().getRealmName()));
        }
    }
    
    /*
     * 
     * @param securityUser
     * @param clearTextPassword
     * @param clearTextPasswordVerify
     * @param isPasswordExpired
     * @return Password
     * @throws PasswordPolicyException
     * @throws ValidationException
     */
    private Password addPasswordForSecurityUser(
        SecurityUser securityUser, 
        ClearTextPassword clearTextPassword, 
        ClearTextPassword clearTextPasswordVerify,
        boolean isPasswordExpired) 
    throws 
        PasswordPolicyException, 
        ValidationException {
      
        PasswordPolicy passwordPolicy = securityUser.getMultiTenancyRealm().getActivePasswordPolicy();
        
        Long creationDate = new Long(System.currentTimeMillis());
        int minPasswordLength = passwordPolicy.getMinPasswordLength();
        
        Password password = new PasswordFactory().createPassword(
            clearTextPassword, 
            clearTextPasswordVerify, 
            minPasswordLength, 
            creationDate, 
            isPasswordExpired);
        
        // Since this is a private method, we know that if the password is blank, then we are in the context of the migration 
        // service, as the public facing password methods in the management service interface disallow blank passwords.
        // TDM: If I had to list anything as a "hack", this would be it.
        if (!ServiceProvider.isPerformingMigration()) {
            passwordPolicy.validateSecurityUserPasswordForPasswordPolicy(
                clearTextPassword.getClearTextPassword(), 
                password,
                securityUser);
        }
        
        securityUser.addPassword(password);
        
        return password;
    }

    /*
     * 
     * @param groupname
     * @param parmDescription
     * @param assignByDefault
     * @param parmMemberUsers
     * @param parentGroup
     * @param isDeletable
     * @param isModifiable
     * @param createAuditEvent
     * @param multiTenancyRealm
     * @return
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     * @throws ObjectNotFoundException
     * @throws StaleObjectException
     */
    private SecurityGroup privateCreateSecurityGroup(
        String groupname,
        String parmDescription,
        boolean assignByDefault,
        Set<AbstractUser> parmMemberUsers,
        SecurityGroup parentGroup,
        boolean isDeletable,
        boolean isModifiable,
        boolean createAuditEvent,
        MultiTenancyRealm multiTenancyRealm) 
    throws
        ObjectAlreadyExistsException,
        ValidationException, 
        ObjectNotFoundException, 
        StaleObjectException {

        Set<AbstractUser> memberUsers = parmMemberUsers;
        if (memberUsers == null) {
            memberUsers = new TreeSet<AbstractUser>(); 
        }
        
        String description = parmDescription;
        if (description == null) {
            description = "";
        }
        
        SecurityGroup securityGroup = this.securityPrincipalDao.createSecurityGroup(
            groupname, 
            description,
            assignByDefault,
            parentGroup,
            isDeletable,
            isModifiable,
            multiTenancyRealm);
        
        List<String> usernameList = new ArrayList<String>();
        Iterator<AbstractUser> iterator = memberUsers.iterator();
        while (iterator.hasNext()) {
            usernameList.add(iterator.next().getUsername());
        }
        this.privateAddUsersToSecurityGroup(usernameList, groupname, createAuditEvent, multiTenancyRealm);        
        
        return securityGroup;
    }
    
    /*
     * 
     * @param rolename
     * @param displayName
     * @param parmDescription
     * @param assignByDefault
     * @param includedRoles
     * @param isDeletable
     * @param isModifiable
     * @param multiTenancyRealm
     * @return
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    private SecurityRole privateCreateSecurityRole( 
        String rolename,
        String displayName,
        String parmDescription,
        boolean assignByDefault,
        Set<SecurityRole> includedRoles,
        boolean isDeletable,
        boolean isModifiable,
        MultiTenancyRealm multiTenancyRealm) 
     throws 
         ObjectAlreadyExistsException, 
         ValidationException {

         String description = parmDescription;
         if (description == null) {
             description = "";
         }
                 
         SecurityRole securityRole = this.securityRoleDao.createSecurityRole(
             rolename, 
             displayName,
             description,
             assignByDefault,
             includedRoles,
             isDeletable,
             isModifiable,
             multiTenancyRealm);
             
         return securityRole;
     }

    /**
     * 
     * @param principalNameList
     * @param roleName
     * @param createAuditEvent
     * @param multiTenancyRealm
     * @return
     * @throws ObjectNotFoundException
     * @throws ObjectAlreadyExistsException
     * @throws ValidationException
     */
    private SecurityRole privateAddSecurityPrincipalsToSecurityRole( 
        Collection<String> principalNameList,
        String roleName,
        boolean createAuditEvent,
        MultiTenancyRealm multiTenancyRealm) 
     throws 
        ObjectNotFoundException,
        ObjectAlreadyExistsException, 
        ValidationException {
         
         SecurityRole securityRole = this.securityRoleDao.getSecurityRole(roleName, multiTenancyRealm);
         
         if (principalNameList.size() > 0) {
         
             Iterator<String> iterator = principalNameList.iterator();
             while (iterator.hasNext()) {
                 String principalName = iterator.next();
                 SecurityPrincipal securityPrincipal = this.securityPrincipalDao.getSecurityPrincipalByPrincipalName(principalName, multiTenancyRealm);
                 securityRole.addMemberSecurityPrincipal(securityPrincipal);
             
                 if (createAuditEvent) {
                     if (securityPrincipal instanceof AbstractUser) {
                         createAuditEvent(new CompuwareSecurityUserUpdatedEvent(
                             (AbstractUser)securityPrincipal,
                             this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                             this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                             this.getCurrentAuthenticationContext().getOriginatingHostname(),
                             "Associated user: [" + securityPrincipal + "]" + TO_ROLE + "[" + securityRole + "].",
                             this.getCurrentAuthenticationContext().getRealmName()));
                     } else {
                         createAuditEvent(new CompuwareSecurityGroupUpdatedEvent(
                             (AbstractGroup)securityPrincipal,
                             this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                             this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                             this.getCurrentAuthenticationContext().getOriginatingHostname(),
                             "Associated group: [" + securityPrincipal + "]" + TO_ROLE + "[" + securityRole + "].",
                             this.getCurrentAuthenticationContext().getRealmName()));
                     }
                 }
             }
                      
             try {
                 this.securityRoleDao.update(securityRole);
             } catch (NonModifiableObjectException nmoe) {
                 // We should not get a non modifiable exception here because all roles are modifiable (but some are non-deletable).
                 throw new ServiceException("Could not associate securityPrincipals: " + principalNameList + " to role: " + roleName + ERROR + nmoe.getLocalizedMessage(), nmoe);                                   
             } catch (StaleObjectException soe) {
                 // This should not happen as we just retrieved the domain object above.
                 throw new ServiceException("Could not associate securityPrincipals: " + principalNameList + " to role: " + roleName + ERROR + soe.getLocalizedMessage(), soe);
             }
         }
                           
         return securityRole;
     }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#authenticateSystemUser(java.lang.String, com.compuware.frameworks.security.service.api.model.SystemUser)
     */
    public boolean authenticateSystemUser(String clearTextPassword, SystemUser systemUser) throws ValidationException {
        return authenticateUser(clearTextPassword, systemUser.getEncodedPassword());
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#authenticateSecurityUser(java.lang.String, com.compuware.frameworks.security.service.api.model.SecurityUser)
     */
    public boolean authenticateSecurityUser(String clearTextPassword, SecurityUser securityUser) throws ValidationException {
        return authenticateUser(clearTextPassword, securityUser.getCurrentPassword().getEncodedPassword());
    }
    
    /*
     * 
     * @param clearTextPassword
     * @param encodedPassword
     * @return
     * @throws ValidationException
     */
    private boolean authenticateUser(String clearTextPassword, String encodedPassword) throws ValidationException {
        return new PasswordFactory().encodePassword(new ClearTextPassword(clearTextPassword)).equalsIgnoreCase(encodedPassword);    
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createMultiTenancyRealm(java.lang.String, java.lang.String, java.lang.String)
     */
    public MultiTenancyRealm createMultiTenancyRealm(
            String realmName,
            String description,
            String ldapBaseDn)
        throws
            ObjectAlreadyExistsException,
            ValidationException {
        
        Set<PasswordPolicy> passwordPolicies = new TreeSet<PasswordPolicy>();
        boolean isDeletable = true;
        boolean isModifiable = true;
        MultiTenancyRealm multiTenancyRealm = super.getMultiTenancyRealmDao().createMultiTenancyRealm(
            realmName, 
            description, 
            ldapBaseDn, 
            passwordPolicies,
            isDeletable,
            isModifiable);
        
        createAuditEvent(new CompuwareSecurityMultiTenancyRealmEvent(
                this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                this.getCurrentAuthenticationContext().getOriginatingHostname(),
                "Created multi tenancy realm: [" + realmName + "].",
                this.getCurrentAuthenticationContext().getRealmName()));        
        
        return multiTenancyRealm;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#updateMultiTenancyRealm(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void updateMultiTenancyRealm(MultiTenancyRealm multiTenancyRealm) 
    throws 
       ObjectNotFoundException, 
       ValidationException, 
       StaleObjectException,
       NonModifiableObjectException {
        
        if (multiTenancyRealm.getPersistentIdentity() == null) {
            throw new ServiceException(CANNOT_UPDATE_NON_PERSISTED_INSTANCE 
                + multiTenancyRealm.getClass().getName() 
                + WITH_NATURAL_IDENTITY 
                + multiTenancyRealm.getNaturalIdentity());
        }
       
        MultiTenancyRealm oldMultiTenancyRealm = (MultiTenancyRealm)super.getMultiTenancyRealmDao().getDomainObjectById(MultiTenancyRealm.class, multiTenancyRealm.getPersistentIdentity());
        if (!oldMultiTenancyRealm.getRealmName().equals(multiTenancyRealm.getRealmName())) {
            throw new IllegalStateException("Cannot update readonly realm name: " + oldMultiTenancyRealm + TO + multiTenancyRealm + ".");
        }   
        
        if (!oldMultiTenancyRealm.getPasswordPolicies().toString().equals(multiTenancyRealm.getPasswordPolicies().toString())) {
            throw new IllegalStateException("Cannot add or remove password policies: " + oldMultiTenancyRealm + " via this method.");
        }           
        super.getMultiTenancyRealmDao().evict(oldMultiTenancyRealm);
        
        super.getMultiTenancyRealmDao().update(multiTenancyRealm);
        
        createAuditEvent(new CompuwareSecurityMultiTenancyRealmEvent(
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            "Updated realm: [" + multiTenancyRealm.getRealmName() + "] with active password policy: [" + multiTenancyRealm.getActivePasswordPolicy() + "], new version: [" + multiTenancyRealm.getVersion() + "].",
            this.getCurrentAuthenticationContext().getRealmName()));        
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deleteMultiTenancyRealm(java.lang.String)
     */
    public void deleteMultiTenancyRealm(String realmName) 
    throws 
        ObjectNotFoundException,
        NonDeletableObjectException {
        
        MultiTenancyRealm multiTenancyRealm = this.getMultiTenancyRealmByName(realmName);
        
        MultiTenancyRealm loggedInRealm = this.getMultiTenancyRealmForSecurityContext();
        
        if (multiTenancyRealm.getRealmName().equalsIgnoreCase(loggedInRealm.getRealmName())) {
            throw new IllegalStateException("Cannot delete realm: [" + realmName + "] because the logged in user + [" + getCurrentlyAuthenticatedUser() + "] is logged into this realm.");
        }
        
        super.getMultiTenancyRealmDao().delete(multiTenancyRealm);
        
        createAuditEvent(new CompuwareSecurityMultiTenancyRealmEvent(
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            "Deleted realm: [" + multiTenancyRealm.getRealmName() + "].",
            this.getCurrentAuthenticationContext().getRealmName()));        
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#createPasswordPolicy(java.lang.String, java.lang.String, boolean, int, int, int, int, int, int, int, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public PasswordPolicy createPasswordPolicy(
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
        ValidationException {
                
        boolean isDeletable = true;
        boolean isModifiable = true;        
        PasswordPolicy passwordPolicy = super.getMultiTenancyRealmDao().createPasswordPolicy(
            passwordPolicyName, 
            description, 
            ageLimit, 
            historyLimit, 
            minNumberOfDigits, 
            minNumberOfChars, 
            minNumberOfSpecialChars, 
            minPasswordLength, 
            maxNumberUnsuccessfulLoginAttempts,
            isDeletable,
            isModifiable,
            multiTenancyRealm); 
                
        createAuditEvent(new CompuwareSecurityPasswordPolicyCreatedEvent(
            passwordPolicy,
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));        
        
        return passwordPolicy;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#updatePasswordPolicy(java.lang.String, java.lang.String, java.lang.String, int, int, int, int, int, int, int)
     */
    public PasswordPolicy updatePasswordPolicy(
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
        NonModifiableObjectException {
        
        MultiTenancyRealm multiTenancyRealm = this.getMultiTenancyRealmByName(realmName);
        PasswordPolicy passwordPolicy = multiTenancyRealm.getPasswordPolicyByPasswordPolicyName(passwordPolicyName);
        
        if (!passwordPolicy.getIsModifiable()) {
            throw new NonModifiableObjectException("Cannot update a non-modifiable instance of: " 
                + passwordPolicy.getClass().getSimpleName() 
                + " with natural identity: " 
                + passwordPolicy.getNaturalIdentity());
        }
        
        passwordPolicy.setAgeLimit(ageLimit);
        passwordPolicy.setDescription(description);
        passwordPolicy.setHistoryLimit(historyLimit);
        passwordPolicy.setMaxNumberUnsuccessfulLoginAttempts(maxNumberUnsuccessfulLoginAttempts);
        passwordPolicy.setMinNumberOfChars(minNumberOfChars);
        passwordPolicy.setMinNumberOfDigits(minNumberOfDigits);
        passwordPolicy.setMinNumberOfSpecialChars(minNumberOfSpecialChars);
        passwordPolicy.setMinPasswordLength(minPasswordLength);
        
        super.getMultiTenancyRealmDao().update(passwordPolicy);
        
        createAuditEvent(new CompuwareSecurityPasswordPolicyUpdatedEvent(
            multiTenancyRealm.getPasswordPolicyByPasswordPolicyName(passwordPolicyName),
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            "Updated password policy: [" + passwordPolicyName + "], new version: [" + multiTenancyRealm.getPasswordPolicyByPasswordPolicyName(passwordPolicyName).getVersion() + "].",
            this.getCurrentAuthenticationContext().getRealmName()));
        
        return passwordPolicy;
    }
    
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#setActivePasswordPolicy(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void setActivePasswordPolicy(
        String passwordPolicyName,
        MultiTenancyRealm multiTenancyRealm)
    throws 
        ObjectNotFoundException,
        ValidationException,
        StaleObjectException,
        NonModifiableObjectException {
        
        multiTenancyRealm.setActivePasswordPolicy(passwordPolicyName);
        
        super.getMultiTenancyRealmDao().update(multiTenancyRealm);
                
        createAuditEvent(new CompuwareSecurityMultiTenancyRealmEvent(
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            "Set active password policy to be: [" + passwordPolicyName + "].",
            this.getCurrentAuthenticationContext().getRealmName()));
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#deletePasswordPolicy(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deletePasswordPolicy(
        String passwordPolicyName,
        MultiTenancyRealm multiTenancyRealm)
    throws 
        ObjectNotFoundException,
        ValidationException,
        StaleObjectException,
        NonDeletableObjectException{

        super.getMultiTenancyRealmDao().deletePasswordPolicy(passwordPolicyName, multiTenancyRealm);
        
        createAuditEvent(new CompuwareSecurityPasswordPolicyDeletedEvent(
            multiTenancyRealm.getPasswordPolicyByPasswordPolicyName(passwordPolicyName),
            this.getCurrentAuthenticationContext().getUserObject().getUsername(),
            this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
            this.getCurrentAuthenticationContext().getOriginatingHostname(),
            this.getCurrentAuthenticationContext().getRealmName()));
    }
    
    /*
     * 
     * @param properties
     * @param comments
     * @param file
     * @throws IOException
     */
    private void writeProperties(Properties properties, String comments, File file) throws IOException {
        
        logger.debug("Saving file: " + file.getAbsolutePath());
        BufferedOutputStream bos = null;
        
        try {
            bos = new BufferedOutputStream(new FileOutputStream(file));            
            properties.store(bos, comments);
        } finally {
            if (bos != null) {
                bos.flush();
                bos.close();                    
            }
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getAllGroupsByCriteria(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public Collection<AbstractGroup> getAllGroupsByCriteria(
        String groupnameCriteria,
        MultiTenancyRealm multiTenancyRealm) throws ValidationException {
 
        int firstResult = 0;
        int maxResults = 100;
        
        return this.securityPrincipalDao.getAllGroupsByCriteria(
            groupnameCriteria, 
            firstResult, 
            maxResults, 
            multiTenancyRealm);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.IManagementService#getSecurityPrincipalByPrincipalName(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityPrincipal getSecurityPrincipalByPrincipalName(
        String securityPrincipalName,    
        MultiTenancyRealm multiTenancyRealm) 
     throws
        ObjectNotFoundException {
        return this.securityPrincipalDao.getSecurityPrincipalByPrincipalName(securityPrincipalName, multiTenancyRealm);
    }    
}