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
 */
package com.compuware.frameworks.security.service.api.management.ldap;

import java.util.List;

import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * <pre>
 * Assumptions about LDAP:
 *   1.) Multitenant realms exist on the same LDAP Server, but are in separate high-level partitions 
 *      (a MultiTenancyRealm in the JFW-Security domain model has a 'baseDN' attribute that is used to hold the top-level 
 *      baseDN that would be used as a search base for all subsequent searches, such as getAllLdapUsernames()) 
 *   2.) SSL is used
 *   3.) Non-anonymous connections
 *   4.) Non-expiring service account 
 *   5.) Service account password is stored in JFW-Security configuration as encrypted (symmetric w/ private key)
 *   6.) Service account password is given as clear text with service account username for initial bind (assumes SSL)
 *    
 * NOTE: Using clear text password over SSL frees JFW-Security from worrying about how the service account password is
 * stored on the LDAP server (i.e. it could be hashed with SHA, SSHA or some other scheme)
 * </pre>
 * 
 * Provide methods for querying lists of user/groups that exist in LDAP. The
 * following properties are needed to facilitate these searches:
 * 
 * <pre>
 * LDAP Configuration (for all realms):
 * ======================================
 * CONNECTION:
 * ldapURL
 * serviceAccountUsername
 * serviceAccountPassword
 * referral
 * referralLimit
 * timeout
 * pageSize
 * 
 * USER SEARCH:
 * usernameAttribute
 * firstnameAttribute
 * lastnameAttribute
 * emailAddressAttribute
 * userSearchBase
 * userSearchFilter
 * 
 * USER GROUPS SEARCH: (i.e. the groups that a user is a member of)
 * userGroupsSearchBase
 * userGroupsSearchFilter
 * 
 * GROUPS SEARCH:
 * groupnameAttribute
 * groupDescriptionAttribute
 * allGroupsSearchBase
 * allGroupsSearchFilter 
 * 
 * Realm-specific Configuration:
 * ======================================
 * baseDN
 * </pre>
 * 
 * @author tmyers
 */
public interface ILdapSearchService {

    /** */
    String EQUALS = "=";
    
    /** */
    String AND = "&";
    
    /** */
    String OR = "|";
    
    /** */
    String LEFT_PAREN = "(";
    
    /** */
    String RIGHT_PAREN = ")";
    
    /** */
    String WILDCARD = "*";
    
    /** */
    String TOKEN_ZERO = "{0}";

    /** */
    String TOKEN_ONE = "{1}";
    
    /**
     * 
     * @param ldapUrl
     * @param serviceAccountUsername
     * @param serviceAccountPassword
     * @param referral
     * @param referralLimit
     * @param timeout
     * @param useTls
     * @param performServerCertificateValidation
     * @param multiTenancyRealm
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    void testLdapConnection(
        String ldapUrl, 
        String serviceAccountUsername, 
        ClearTextPassword serviceAccountPassword, 
        String referral, 
        int referralLimit,
        int timeout,
        boolean useTls,
        boolean performServerCertificateValidation,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException;

    /**
     * 
     * @param ldapUrl
     * @param serviceAccountUsername
     * @param serviceAccountPassword
     * @param referral
     * @param referralLimit
     * @param timeout
     * @param useTls
     * @param performServerCertificateValidation
     * @param usernameAttribute
     * @param emailAddressAttribute
     * @param firstNameAttribute
     * @param lastNameAttribute
     * @param userSearchBase
     * @param userSearchFilter
     * @param usernameValue
     * @param groupnameAttribute
     * @param groupDescriptionAttribute
     * @param userGroupsSearchBase
     * @param userGroupsSearchFilter
     * @param multiTenancyRealm
     * @return ShadowSecurityUser
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     * @throws ObjectNotFoundException
     */
    ShadowSecurityUser testGetLdapUserWithGroups(
        String ldapUrl, 
        String serviceAccountUsername, 
        ClearTextPassword serviceAccountPassword, 
        String referral, 
        int referralLimit,
        int timeout,
        boolean useTls,
        boolean performServerCertificateValidation,
        String usernameAttribute,
        String emailAddressAttribute,
        String firstNameAttribute,
        String lastNameAttribute,            
        String userSearchBase, 
        String userSearchFilter,
        String usernameValue,
        String groupnameAttribute, 
        String groupDescriptionAttribute, 
        String userGroupsSearchBase,
        String userGroupsSearchFilter,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException,
        ObjectNotFoundException;
    
    /**
     * 
     * @param ldapUrl
     * @param serviceAccountUsername
     * @param serviceAccountPassword
     * @param referral
     * @param referralLimit
     * @param timeout
     * @param useTls
     * @param performServerCertificateValidation
     * @param usernameAttribute
     * @param userDn
     * @param groupnameAttribute
     * @param groupDescriptionAttribute
     * @param userGroupsSearchBase
     * @param userGroupsSearchFilter
     * @param multiTenancyRealm
     * @return List<ShadowSecurityGroup>
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    List<ShadowSecurityGroup> testGetLdapGroupsForLdapUser(
        String ldapUrl, 
        String serviceAccountUsername, 
        ClearTextPassword serviceAccountPassword, 
        String referral,
        int referralLimit, 
        int timeout, 
        boolean useTls,
        boolean performServerCertificateValidation,
        String usernameAttribute, 
        String userDn,
        String groupnameAttribute, 
        String groupDescriptionAttribute, 
        String userGroupsSearchBase,
        String userGroupsSearchFilter,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException;
    
    /**
     * Returns the first 100 users that would be returned by a call to getLdapUsersByCriteria() where all criteria specified are null.
     * 
     * @param ldapUrl
     * @param serviceAccountUsername
     * @param serviceAccountPassword
     * @param referral
     * @param referralLimit
     * @param timeout
     * @param useTls
     * @param performServerCertificateValidation
     * @param userSearchBase
     * @param userSearchFilter
     * @return List<ShadowSecurityUser>
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    List<ShadowSecurityUser> testGetAllLdapUsers(
        String ldapUrl, 
        String serviceAccountUsername, 
        ClearTextPassword serviceAccountPassword, 
        String referral, 
        int referralLimit,
        int timeout, 
        boolean useTls,
        boolean performServerCertificateValidation,
        String usernameAttribute,
        String emailAddressAttribute,
        String firstNameAttribute,
        String lastNameAttribute,            
        String userSearchBase, 
        String userSearchFilter,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException;
    
    /**
     * Returns the first 100 groups that would be returned by a call to getLdapGroupsByCriteria() where all criteria specified are null.
     * 
     * @param ldapUrl
     * @param serviceAccountUsername
     * @param serviceAccountPassword
     * @param referral
     * @param referralLimit
     * @param timeout
     * @param useTls
     * @param performServerCertificateValidation
     * @param groupnameAttribute
     * @param groupDescriptionAttribute
     * @param allGroupsSearchBase
     * @param allGroupsSearchFilter
     * @param multiTenancyRealm
     * @return List<ShadowSecurityGroup>
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    List<ShadowSecurityGroup> testGetAllLdapGroups(
        String ldapUrl, 
        String serviceAccountUsername, 
        ClearTextPassword serviceAccountPassword, 
        String referral, 
        int referralLimit,
        int timeout,
        boolean useTls,
        boolean performServerCertificateValidation,
        String groupnameAttribute, 
        String groupDescriptionAttribute,
        String allGroupsSearchBase, 
        String allGroupsSearchFilter,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException;

    /**
     * 
     * @param usernameValue
     * @param multiTenancyRealm The top level grouping for all domain objects for a given organization.
     * @return ShadowSecurityUser
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     * @throws ObjectNotFoundException
     */
    ShadowSecurityUser getLdapUser(
        String usernameValue,
        MultiTenancyRealm multiTenancyRealm)
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException,
        ObjectNotFoundException;
    
    /**
     * Retrieves a map of all LDAP users that meet the given criteria (if all criteria are null, 
     * then return as many users as allowed by <code>maxResults</code>):
     * 
     * @param usernameCriteria
     * @param firstNameCriteria
     * @param lastNameCriteria
     * @param emailAddressCriteria
     * @param isOrQuery If true, the search is a logical OR query, logical AND otherwise.
     * @param pageSize
     * @param maxResults If non-zero, returns at most <code>maxResults</code> users; otherwise all qualifying users are returned.
     * @param multiTenancyRealm
     * @return List<ShadowSecurityUser>
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    List<ShadowSecurityUser> getLdapUsersByCriteria(
        String usernameCriteria,
        String firstNameCriteria, 
        String lastNameCriteria, 
        String emailAddressCriteria,
        boolean isOrQuery, 
        int pageSize,
        int maxResults,
        MultiTenancyRealm multiTenancyRealm)
    throws
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException;

    /**
     * 
     * @param userDn
     * @param multiTenancyRealm
     * @return List<String>
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    List<String> getLdapGroupsForLdapUserDn(
        String userDn, 
        MultiTenancyRealm multiTenancyRealm)
    throws 
        InvalidConnectionException,
        InvalidCredentialsException;    

    /**
     * Retrieves a map of all LDAP groups that meet the given criteria (if all criteria are null, 
     * then return as many groups as allowed by <code>maxResults</code>):
     * 
     * @param groupnameCriteria
     * @param pageSize
     * @param maxResults If non-zero, returns at most <code>maxResults</code> groups; otherwise all qualifying groups are returned.
     * @param multiTenancyRealm
     * @return List<ShadowSecurityUser>
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    List<ShadowSecurityGroup> getLdapGroupsByCriteria(
        String groupnameCriteria, 
        int pageSize, 
        int maxResults,
        MultiTenancyRealm multiTenancyRealm)
    throws
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException;
}