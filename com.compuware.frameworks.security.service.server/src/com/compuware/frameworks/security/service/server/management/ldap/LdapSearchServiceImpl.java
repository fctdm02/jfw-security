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
package com.compuware.frameworks.security.service.server.management.ldap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;

import org.apache.log4j.Logger;
import org.springframework.ldap.BadLdapGrammarException;
import org.springframework.ldap.CommunicationException;
import org.springframework.ldap.control.PagedResultsRequestControl;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityLdapConfiguration;
import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.configuration.IConfigurationService;
import com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;
import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService;
import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.DomainObject;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipalComparator;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;
import com.compuware.frameworks.security.service.server.AbstractService;

/**
 * 
 * @author tmyers
 * 
 */
@SuppressWarnings("deprecation")
public final class LdapSearchServiceImpl extends AbstractService implements ILdapSearchService {
    
    /* */
    private final Logger logger = Logger.getLogger(LdapSearchServiceImpl.class);
    
    /* */
    private IConfigurationService configurationService;

    /* */
    private SearchControls searchControls;
    
    /**
     * 
     * @param eventService
     * @param auditService
     * @param configurationService
     * @param multiTenancyRealmDao
     */
    public LdapSearchServiceImpl(IEventService eventService,
        IAuditService auditService,
        IConfigurationService configurationService,
        IMultiTenancyRealmDao multiTenancyRealmDao) {
        super(auditService, eventService, multiTenancyRealmDao);        
        setConfigurationService(configurationService);
        searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);            
    }

    /**
     * 
     * @param configurationService
     */
    public void setConfigurationService(IConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#testLdapConnection(java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.ClearTextPassword, java.lang.String, int, int, boolean, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void testLdapConnection(
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
        InvalidCredentialsException {
        
        CompuwareSecurityLdapContextSource ldapContext = buildLdapContext(
                ldapUrl, 
                serviceAccountUsername,
                serviceAccountPassword,
                referral, 
                referralLimit, 
                timeout,
                useTls,
                performServerCertificateValidation,
                multiTenancyRealm);

        ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();        
        try {
            Thread.currentThread().setContextClassLoader(CompuwareSecuritySslSocketFactory.class.getClassLoader());            
            ldapContext.getReadOnlyContext().getNameInNamespace();
        } catch (NamingException ne) {
            throw new InvalidConnectionException("Could not connect to LDAP Server, error: " + ne.getMessage(), ne);
        } catch (CommunicationException ce) {
            throw new InvalidConnectionException("Could not connect to LDAP Server, error: " + ce.getMessage(), ce);
        } catch (org.springframework.ldap.AuthenticationException ae) {
            throw new InvalidCredentialsException("Could not authenticate to LDAP Server, error: " + ae.getMessage(), ae);
        } finally {
            Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#testGetLdapUserWithGroups(java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.ClearTextPassword, java.lang.String, int, int, boolean, boolean, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public ShadowSecurityUser testGetLdapUserWithGroups(
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
        String parmUserSearchFilter,
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
        ObjectNotFoundException {
        
        String userSearchFilter = parmUserSearchFilter.replace(
            TOKEN_ZERO,
            usernameValue);
                
        List<ShadowSecurityUser> shadowSecurityUsers = this.testGetAllLdapUsers(
            ldapUrl, 
            serviceAccountUsername, 
            serviceAccountPassword, 
            referral, 
            referralLimit, 
            timeout, 
            useTls,
            performServerCertificateValidation,
            usernameAttribute, 
            emailAddressAttribute, 
            firstNameAttribute, 
            lastNameAttribute, 
            userSearchBase, 
            userSearchFilter, 
            multiTenancyRealm);
        
        ShadowSecurityUser shadowSecurityUser = null;
        Iterator<ShadowSecurityUser> iterator = shadowSecurityUsers.iterator();
        while (iterator.hasNext()) {
            
            ShadowSecurityUser user = iterator.next();
            if (user.getUsername().equalsIgnoreCase(usernameValue)) {
                shadowSecurityUser = user;
                break;
            }
        }
                
        if (shadowSecurityUser != null) {

            List<ShadowSecurityGroup> ldapGroups = this.testGetLdapGroupsForLdapUser(
                ldapUrl,
                serviceAccountUsername,
                serviceAccountPassword,
                referral,
                referralLimit,
                timeout,
                useTls,
                performServerCertificateValidation,
                usernameAttribute,
                shadowSecurityUser.getShadowedUserLdapDN(),
                groupnameAttribute,
                groupDescriptionAttribute,
                userGroupsSearchBase,
                userGroupsSearchFilter,
                multiTenancyRealm); 
            shadowSecurityUser.setUserLdapGroups(ldapGroups);
            return shadowSecurityUser;
        } else {
            throw new ObjectNotFoundException("Could not find LDAP user with username: [" 
                + usernameValue 
                + "] with LDAP URL: [" 
                + ldapUrl
                + "], with usernameAttribute: [" 
                + usernameAttribute 
                + "] and userSearchBase: [" 
                + userSearchBase
                + "].");
        }            
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#testGetLdapGroupsForLdapUser(java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.ClearTextPassword, java.lang.String, int, int, boolean, boolean, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public List<ShadowSecurityGroup> testGetLdapGroupsForLdapUser(
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
        String parmUserGroupsSearchFilter,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException {
        
        String userGroupsSearchFilter = parmUserGroupsSearchFilter.replace(TOKEN_ZERO, userDn);
                
        CompuwareSecurityLdapContextSource ldapContext = buildLdapContext(
                ldapUrl, 
                serviceAccountUsername,
                serviceAccountPassword,
                referral, 
                referralLimit, 
                timeout,
                useTls,
                performServerCertificateValidation,
                multiTenancyRealm);                                  
        
        SpringSecurityLdapTemplate springSecurityLdapTemplate = buildSpringSecurityLdapTemplate(ldapContext);
        
        ContextMapper contextMapper = buildShadowSecurityGroupContextMapper(
                groupnameAttribute, 
                groupDescriptionAttribute,
                multiTenancyRealm);            
        
        return this.getLdapUserGroups(
                springSecurityLdapTemplate, 
                contextMapper, 
                userGroupsSearchFilter, 
                userGroupsSearchBase);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#testGetAllLdapUsers(java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.ClearTextPassword, java.lang.String, int, int, boolean, boolean, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public List<ShadowSecurityUser> testGetAllLdapUsers(
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
        String parmUserSearchFilter,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException {
        
        String userSearchFilter = parmUserSearchFilter.replace(TOKEN_ZERO, WILDCARD);
        
        CompuwareSecurityLdapContextSource ldapContext = buildLdapContext(
                ldapUrl, 
                serviceAccountUsername,
                serviceAccountPassword,
                referral, 
                referralLimit, 
                timeout,
                useTls,
                performServerCertificateValidation,
                multiTenancyRealm);                                  
        
        SpringSecurityLdapTemplate springSecurityLdapTemplate = buildSpringSecurityLdapTemplate(ldapContext);
                                
        ContextMapper contextMapper = buildShadowSecurityUserContextMapper(
                usernameAttribute, 
                emailAddressAttribute,
                firstNameAttribute,
                lastNameAttribute,
                multiTenancyRealm);            
        
        int pageSize = 100;
        int maxResults = 100;
        
        return this.getLdapUsers(
                springSecurityLdapTemplate, 
                contextMapper, 
                userSearchFilter, 
                userSearchBase,
                pageSize,
                maxResults);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#testGetAllLdapGroups(java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.ClearTextPassword, java.lang.String, int, int, boolean, boolean, java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public List<ShadowSecurityGroup> testGetAllLdapGroups(
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
        String parmAllGroupsSearchFilter,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException {
        
        String allGroupsSearchFilter = parmAllGroupsSearchFilter.replace(TOKEN_ZERO, groupnameAttribute);
        allGroupsSearchFilter = allGroupsSearchFilter.replace(TOKEN_ONE, WILDCARD);
        
        CompuwareSecurityLdapContextSource ldapContext = buildLdapContext(
                ldapUrl, 
                serviceAccountUsername,
                serviceAccountPassword,
                referral, 
                referralLimit, 
                timeout,
                useTls,
                performServerCertificateValidation,
                multiTenancyRealm);                                  
        
        SpringSecurityLdapTemplate springSecurityLdapTemplate = buildSpringSecurityLdapTemplate(ldapContext);
                                
        ContextMapper contextMapper = buildShadowSecurityGroupContextMapper(
                groupnameAttribute, 
                groupDescriptionAttribute,
                multiTenancyRealm);                            
        
        int pageSize = 100;
        int maxResults = 100;
        
        return this.getLdapGroups(
                springSecurityLdapTemplate, 
                contextMapper, 
                allGroupsSearchFilter, 
                allGroupsSearchBase,
                pageSize,
                maxResults);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#getLdapUser(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public ShadowSecurityUser getLdapUser(
        String usernameValue,
        MultiTenancyRealm multiTenancyRealm)
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException,
        ObjectNotFoundException {
        
        SpringSecurityLdapTemplate springSecurityLdapTemplate = initialize(multiTenancyRealm);
        
        ILdapConfiguration ldapConfiguration = configurationService.getLdapConfiguration();
        
        String userSearchBase = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY);
        String userSearchFilter = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY);
        
        userSearchFilter = userSearchFilter.replace(TOKEN_ZERO, usernameValue);

        ContextMapper contextMapper = buildShadowSecurityUserContextMapper(
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY), 
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY),
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY),
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY),
                multiTenancyRealm);            
        
        int pageSize = 1;
        int maxResults = 1;
        
        List<ShadowSecurityUser> shadowSecurityUsers = this.getLdapUsers(
                springSecurityLdapTemplate, 
                contextMapper, 
                userSearchFilter, 
                userSearchBase,
                pageSize,
                maxResults);
        
        if (shadowSecurityUsers.size() == 1) {
            return (ShadowSecurityUser)shadowSecurityUsers.get(0);
        } else {
            throw new ObjectNotFoundException("Could not find LDAP user with the given search filter: " + userSearchFilter + " from search base: " + userSearchBase);
        }            
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#getLdapUsersByCriteria(java.lang.String, java.lang.String, java.lang.String, java.lang.String, boolean, int, int, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public List<ShadowSecurityUser> getLdapUsersByCriteria(
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
        InvalidCredentialsException {
        
        SpringSecurityLdapTemplate springSecurityLdapTemplate = initialize(multiTenancyRealm);
        
        ILdapConfiguration ldapConfiguration = configurationService.getLdapConfiguration();
                        
        String userSearchBase = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY);
        String userSearchFilter = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY); 
        String emailAddressAttribute = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY);
        String firstNameAttribute = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY);
        String lastNameAttribute = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY);
                
        String firstNameCriterion = null;
        if (firstNameCriteria != null && !firstNameCriteria.isEmpty()) {
            if (firstNameCriteria.length() > 256) {
                throw new ValidationException(ValidationException.FIELD_FIRST_NAME, ValidationException.REASON_CANNOT_BE_GREATER_THAN_256_CHARS);
            }
            firstNameCriterion = LEFT_PAREN + firstNameAttribute + EQUALS + WILDCARD + firstNameCriteria + WILDCARD + RIGHT_PAREN;
        }

        String lastNameCriterion = null;
        if (lastNameCriteria != null && !lastNameCriteria.isEmpty()) {
            if (lastNameCriteria.length() > 256) {
                throw new ValidationException(ValidationException.FIELD_LAST_NAME, ValidationException.REASON_CANNOT_BE_GREATER_THAN_256_CHARS);
            }           
            lastNameCriterion = LEFT_PAREN + lastNameAttribute + EQUALS + WILDCARD + lastNameCriteria + WILDCARD + RIGHT_PAREN;
        }
        
        String emailAddressCriterion = null;
        if (emailAddressCriteria != null && !emailAddressCriteria.isEmpty()) {
            if (emailAddressCriteria.length() > 256) {
                throw new ValidationException(ValidationException.FIELD_EMAIL_ADDRESS, ValidationException.REASON_CANNOT_BE_GREATER_THAN_256_CHARS);
            }
            emailAddressCriterion = LEFT_PAREN + emailAddressAttribute + EQUALS + WILDCARD + emailAddressCriteria + WILDCARD + RIGHT_PAREN;
        }
        
        String operator = null;
        if (isOrQuery) {
            operator = OR;
        } else {
            operator = AND;
        }
        
        String criteriaSearchFilter = null;        
        if (firstNameCriterion == null && lastNameCriterion == null && emailAddressCriterion != null) {
            criteriaSearchFilter = emailAddressCriterion;            
        } else if (firstNameCriterion == null && lastNameCriterion != null && emailAddressCriterion == null) {
            criteriaSearchFilter = lastNameCriterion;            
        } else if (firstNameCriterion == null && lastNameCriterion != null && emailAddressCriterion != null) {
            criteriaSearchFilter = LEFT_PAREN + operator + lastNameCriterion + emailAddressCriterion + RIGHT_PAREN;
        } else if (firstNameCriterion != null && lastNameCriterion == null && emailAddressCriterion == null) {
            criteriaSearchFilter = firstNameCriterion;            
        } else if (firstNameCriterion != null && lastNameCriterion == null && emailAddressCriterion != null) {
            criteriaSearchFilter = LEFT_PAREN + operator + firstNameCriterion + emailAddressCriterion + RIGHT_PAREN;            
        } else if (firstNameCriterion != null && lastNameCriterion != null && emailAddressCriterion == null) {
            criteriaSearchFilter = LEFT_PAREN + operator + firstNameCriterion + lastNameCriterion + RIGHT_PAREN;            
        } else if (firstNameCriterion != null && lastNameCriterion != null && emailAddressCriterion != null) {
            criteriaSearchFilter = LEFT_PAREN + operator + firstNameCriterion + LEFT_PAREN + operator + lastNameCriterion + emailAddressCriterion + RIGHT_PAREN + RIGHT_PAREN;
        }
        
        
        String usernameCriterion = null;
        if (usernameCriteria != null && !usernameCriteria.isEmpty()) {
            if (usernameCriteria.length() > 256) {
                throw new ValidationException(ValidationException.FIELD_USERNAME, ValidationException.REASON_CANNOT_BE_GREATER_THAN_256_CHARS);
            }
            if (!usernameCriteria.equals(DomainObject.ORACLE_EMPTY_STRING_ID)) {
                usernameCriterion = userSearchFilter.replace(TOKEN_ZERO, WILDCARD + usernameCriteria + WILDCARD);
            }
        } else {
            usernameCriterion = userSearchFilter.replace(TOKEN_ZERO, WILDCARD);
        }
        
        if (criteriaSearchFilter != null && usernameCriterion != null) {
            criteriaSearchFilter = LEFT_PAREN + AND + usernameCriterion + criteriaSearchFilter + RIGHT_PAREN;
        } else if (usernameCriterion != null) {
            criteriaSearchFilter = usernameCriterion;
        } else if (criteriaSearchFilter == null) {
            throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_AT_LEAST_ONE_SEARCH_CRITERIA_MUST_BE_SPECIFIED);
        }

        
        logger.debug("Using search criteria: " + criteriaSearchFilter);

        ContextMapper contextMapper = buildShadowSecurityUserContextMapper(
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY), 
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY),
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY),
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY),
                multiTenancyRealm);            
        
        List<ShadowSecurityUser> shadowSecurityUsers = this.getLdapUsers(
                springSecurityLdapTemplate, 
                contextMapper, 
                criteriaSearchFilter, 
                userSearchBase,
                pageSize,
                maxResults);
                
        return shadowSecurityUsers;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#getLdapGroupsForLdapUserDn(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public List<String> getLdapGroupsForLdapUserDn(
        String userDn, 
        MultiTenancyRealm multiTenancyRealm) 
    throws  
        InvalidConnectionException,
        InvalidCredentialsException {
        
        SpringSecurityLdapTemplate springSecurityLdapTemplate = initialize(multiTenancyRealm);
        
        ILdapConfiguration ldapConfiguration = configurationService.getLdapConfiguration();
        
        String userGroupsSearchBase = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY);
        String userGroupsSearchFilter = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY);
        
        userGroupsSearchFilter = userGroupsSearchFilter.replace(TOKEN_ZERO, userDn);

        ContextMapper contextMapper = buildShadowSecurityGroupContextMapper(
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY), 
                ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY),
                multiTenancyRealm);            
        
        List<String> userLdapGroups = new ArrayList<String>();
        
        try {
            List<ShadowSecurityGroup> shadowSecurityGroupList = this.getLdapUserGroups(
                    springSecurityLdapTemplate, 
                    contextMapper, 
                    userGroupsSearchFilter, 
                    userGroupsSearchBase);
            
            
            Iterator<ShadowSecurityGroup> iterator = shadowSecurityGroupList.iterator();
            while (iterator.hasNext()) {
                ShadowSecurityGroup shadowSecurityGroup = iterator.next();
                userLdapGroups.add(shadowSecurityGroup.getGroupname());
            }
        } catch (ValidationException ve) {
            throw new ServiceException("Could not retrieve LDAP groups for LDAP user with DN: " + userDn + ", error: " + ve.getMessage(), ve);            
        }
        
        return userLdapGroups;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService#getLdapGroupsByCriteria(java.lang.String, int, int, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public List<ShadowSecurityGroup> getLdapGroupsByCriteria(
        String groupnameCriteria,
        int pageSize,
        int maxResults,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException {

        SpringSecurityLdapTemplate springSecurityLdapTemplate = initialize(multiTenancyRealm);
        
        ILdapConfiguration ldapConfiguration = configurationService.getLdapConfiguration();
                
        String groupnameAttribute = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY);
        String descriptionAttribute = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY);
        String groupListSearchBase = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY);
        String groupListSearchFilter = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY);
        
        groupListSearchFilter = groupListSearchFilter.replace(TOKEN_ZERO, groupnameAttribute);
        if (groupnameCriteria == null || groupnameCriteria.equals(WILDCARD)) {
            groupListSearchFilter = groupListSearchFilter.replace(TOKEN_ONE, WILDCARD);
        } else {
            groupListSearchFilter = groupListSearchFilter.replace(TOKEN_ONE, WILDCARD + groupnameCriteria + WILDCARD);    
        }
        
        ContextMapper contextMapper = buildShadowSecurityGroupContextMapper(
                groupnameAttribute, 
                descriptionAttribute,
                multiTenancyRealm);            
        
        List<ShadowSecurityGroup> shadowSecurityGroups = this.getLdapGroups(
                springSecurityLdapTemplate, 
                contextMapper, 
                groupListSearchFilter, 
                groupListSearchBase,
                pageSize,
                maxResults);
                
        return shadowSecurityGroups;
    }

    /*
     * 
     * @param multiTenancyRealm
     * @return
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    private SpringSecurityLdapTemplate initialize(
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        InvalidConnectionException, 
        InvalidCredentialsException {
        
        ILdapConfiguration ldapConfiguration = configurationService.getLdapConfiguration();

        String ldapUrl = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_URL_KEY); 
        String serviceAccountUsername = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY);
        ClearTextPassword serviceAccountPassword = new ClearTextPassword(ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY));
        String referral = ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_REFERRAL_KEY);
        int referralLimit = Integer.parseInt(ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY)); 
        int timeout = Integer.parseInt(ldapConfiguration.getConfigurationValue(ILdapConfiguration.LDAP_TIMEOUT_KEY));
        boolean useTls = false;
        String encryptionMethod = ldapConfiguration.getEncryptionMethod();
        if (encryptionMethod.equals(ILdapConfiguration.LDAP_ENCRYPTION_METHOD_TLS)) {
            useTls = true;
        }
        boolean performServerCertificateValidation = ldapConfiguration.getPerformServerCertificateValidation();
        
        CompuwareSecurityLdapContextSource ldapContext = buildLdapContext(
                ldapUrl, 
                serviceAccountUsername,
                serviceAccountPassword,
                referral, 
                referralLimit, 
                timeout,
                useTls,
                performServerCertificateValidation,
                multiTenancyRealm);                    
        
        SpringSecurityLdapTemplate springSecurityLdapTemplate = buildSpringSecurityLdapTemplate(ldapContext);
        return springSecurityLdapTemplate;
    }

    /*
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
     * @return
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    private CompuwareSecurityLdapContextSource buildLdapContext(
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
        InvalidConnectionException, 
        InvalidCredentialsException {
        
        Map<String, String> ldapEnvironmentProperties = new HashMap<String, String>();

        String encryptionMethod = null;
        if (ldapUrl.toLowerCase().startsWith(ICompuwareSecurityLdapConfiguration.LDAP_URL_SSL_PROTOCOL_PREFIX)) {
            encryptionMethod = ICompuwareSecurityLdapConfiguration.LDAP_ENCRYPTION_METHOD_SSL;
        } else {
            encryptionMethod = ICompuwareSecurityLdapConfiguration.LDAP_ENCRYPTION_METHOD_NONE;
        }
        
        ldapEnvironmentProperties.put("java.naming.ldap.version", "3");
        ldapEnvironmentProperties.put("java.naming.referral", referral);
        ldapEnvironmentProperties.put("java.naming.ldap.referral.limit", Integer.toString(referralLimit));
        ldapEnvironmentProperties.put("com.sun.jndi.ldap.read.timeout", Integer.toString(timeout));
        ldapEnvironmentProperties.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(timeout));
        ldapEnvironmentProperties.put("java.naming.security.protocol", encryptionMethod);

        CompuwareSecurityLdapContextSource ldapContext = null;
        ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            String ldapUrlWithRealmBaseDn = ldapUrl + multiTenancyRealm.getLdapBaseDn(); 
            Thread.currentThread().setContextClassLoader(CompuwareSecuritySslSocketFactory.class.getClassLoader());
            
            ldapContext = new CompuwareSecurityLdapContextSource(                    
                ldapUrlWithRealmBaseDn, 
                serviceAccountUsername, 
                serviceAccountPassword.getClearTextPassword(), 
                referral, 
                Boolean.toString(useTls),
                Boolean.toString(performServerCertificateValidation),
                ldapEnvironmentProperties);
                        
            StringBuilder sb = new StringBuilder(512);
            sb.append("Initializing CompuwareSecurityLdapContextSource with ldapUrl: ");
            sb.append(ldapUrl);
            sb.append(", serviceAccountUsername: ");
            sb.append(serviceAccountUsername);
            sb.append(", serviceAccountPassword: [PROTECTED], referral: ");
            sb.append(referral);
            sb.append(", referralLimit: ");
            sb.append(referralLimit);
            sb.append(", timeout: ");
            sb.append(timeout);
            sb.append(", useTls: ");
            sb.append(Boolean.toString(useTls));
            sb.append(", performServerCertificateValidation: ");
            sb.append(Boolean.toString(performServerCertificateValidation));
            sb.append(" ldapEnvironmentProperties: ");
            sb.append(ldapEnvironmentProperties);
            sb.append(" in realm: ");
            sb.append(multiTenancyRealm.getRealmName());
            logger.debug(sb.toString());
            
            ldapContext.afterPropertiesSet();
        } catch (BadLdapGrammarException blge) {
            throw new InvalidConnectionException("Could not connect to LDAP Server, error: " + blge.getMessage(), blge);
        } catch (InvalidNameException ine) {
            throw new InvalidCredentialsException("Could not authenticate to LDAP, error: " + ine.getMessage(), ine);            
        } catch (Exception e) {
            throw new ServiceException("Unexpected exception trying to create LDAP context, error: " + e.getMessage(), e);
        } finally {
            Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
        
        return ldapContext;
    }
    
    /*
     * 
     * @param ldapContext
     * @return
     */
    private SpringSecurityLdapTemplate buildSpringSecurityLdapTemplate(CompuwareSecurityLdapContextSource ldapContext) {
        
        SpringSecurityLdapTemplate springSecurityLdapTemplate = null;
        
        try {
            springSecurityLdapTemplate = new SpringSecurityLdapTemplate(ldapContext);
            springSecurityLdapTemplate.setIgnorePartialResultException(true);
            springSecurityLdapTemplate.afterPropertiesSet();
        } catch (Exception e) {
            throw new ServiceException("Unexpected exception trying to create Spring Security LDAP Template, error: " + e.getMessage(), e);
        }
        
        return springSecurityLdapTemplate;
    }

    /*
     * 
     * @param springSecurityLdapTemplate
     * @param contextMapper
     * @param userSearchFilter
     * @param userSearchBase
     * @param pageSize
     * @param maxResults if -1, then return all results
     * @return List<ShadowSecurityUser>
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    private List<ShadowSecurityUser> getLdapUsers(
        SpringSecurityLdapTemplate springSecurityLdapTemplate,
        ContextMapper contextMapper,
        String userSearchFilter,
        String userSearchBase,
        int pageSize,
        int maxResults)
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException {
        
        List<ShadowSecurityUser> shadowSecurityUsers = new ArrayList<ShadowSecurityUser>();

        ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(CompuwareSecuritySslSocketFactory.class.getClassLoader());
            
            // Perform a series of paged searches, as the entire list would result in a size limit exceeded exception.
            PagedResultsRequestControl control = new PagedResultsRequestControl(pageSize, null);
            do {
                List<?> pageGroupList = springSecurityLdapTemplate.search(
                        userSearchBase,
                        userSearchFilter,
                        searchControls,
                        contextMapper, 
                        control);
    
                Iterator<?> iterator = pageGroupList.iterator();
                while (iterator.hasNext()) {
                    if (maxResults == -1 || shadowSecurityUsers.size() < maxResults) {
                        Object object = iterator.next();
                        if (object != null && object instanceof ShadowSecurityUser) {
                            shadowSecurityUsers.add((ShadowSecurityUser)object);    
                        }
                    } else {
                        break;
                    }
                }
                
                control = new PagedResultsRequestControl(pageSize, control.getCookie());
                
             } while (control.getCookie().getCookie() != null && (maxResults == -1 || shadowSecurityUsers.size() < maxResults));
            
        } catch (org.springframework.ldap.InvalidNameException ine) {
            throw new InvalidCredentialsException("getLdapUsers(): Could not authenticate to LDAP, error: " + ine.getMessage(), ine);            
        } catch (org.springframework.ldap.AuthenticationException ae) {
            throw new InvalidCredentialsException("getLdapUsers(): Could not authenticate to LDAP, error: " + ae.getMessage(), ae);
        } catch (CommunicationException ce) {
            throw new InvalidConnectionException("getLdapUsers(): Could not connect to LDAP Server, error: " + ce.getMessage(), ce);            
        } finally {
            Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
        
        Collections.sort(shadowSecurityUsers, new SecurityPrincipalComparator());
                
        return shadowSecurityUsers;
    }

    /*
     * 
     * @param springSecurityLdapTemplate
     * @param contextMapper
     * @param userGroupsSearchFilter
     * @return List<ShadowSecurityGroup>
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    private List<ShadowSecurityGroup> getLdapUserGroups(
        SpringSecurityLdapTemplate springSecurityLdapTemplate,
        ContextMapper contextMapper,
        String userGroupsSearchFilter,
        String userGroupsSearchBase)
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException {
        
        List<ShadowSecurityGroup> ldapUserGroups = new ArrayList<ShadowSecurityGroup>();
        
        ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(CompuwareSecuritySslSocketFactory.class.getClassLoader());
                        
            List<?> list = springSecurityLdapTemplate.search(
                    userGroupsSearchBase, 
                    userGroupsSearchFilter, 
                    contextMapper);
            
            Iterator<?> iterator = list.iterator();
            while (iterator.hasNext()) {
                ldapUserGroups.add((ShadowSecurityGroup)iterator.next());
            }
                                    
        } catch (org.springframework.ldap.InvalidNameException ine) {
            throw new InvalidCredentialsException("getLdapUserGroups(): Could not authenticate to LDAP, error: " + ine.getMessage(), ine);            
        } catch (org.springframework.ldap.AuthenticationException ae) {
            throw new InvalidCredentialsException("getLdapUserGroups(): Could not authenticate to LDAP, error: " + ae.getMessage(), ae);
        } catch (CommunicationException ce) {
            throw new InvalidConnectionException("getLdapUserGroups(): Could not connect to LDAP Server, error: " + ce.getMessage(), ce);            
        } finally {
            Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
        
        Collections.sort(ldapUserGroups, new SecurityPrincipalComparator());
        
        return ldapUserGroups;
    }

    /*
     * 
     * @param springSecurityLdapTemplate
     * @param contextMapper
     * @param allGroupsSearchFilter
     * @param allGroupsSearchBase
     * @param pageSize
     * @param maxResults if -1, then return all results
     * @return List<ShadowSecurityGroup>
     * @throws ValidationException
     * @throws InvalidConnectionException
     * @throws InvalidCredentialsException
     */
    private List<ShadowSecurityGroup> getLdapGroups(
        SpringSecurityLdapTemplate springSecurityLdapTemplate,
        ContextMapper contextMapper,
        String allGroupsSearchFilter,
        String allGroupsSearchBase,
        int pageSize,
        int maxResults)
    throws 
        ValidationException,
        InvalidConnectionException,
        InvalidCredentialsException {
        
        List<ShadowSecurityGroup> shadowSecurityGroups = new ArrayList<ShadowSecurityGroup>();
        
        ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(CompuwareSecuritySslSocketFactory.class.getClassLoader());
                                    
            // Perform a series of paged searches, as the entire list would result in a size limit exceeded exception.
            PagedResultsRequestControl control = new PagedResultsRequestControl(pageSize, null);
            do {
                List<?> pageGroupList = springSecurityLdapTemplate.search(
                        allGroupsSearchBase,
                        allGroupsSearchFilter,
                        searchControls,
                        contextMapper, 
                        control);
    
                Iterator<?> iterator = pageGroupList.iterator();
                while (iterator.hasNext()) {
                    if (maxResults == -1 || shadowSecurityGroups.size() < maxResults) {
                        shadowSecurityGroups.add((ShadowSecurityGroup)iterator.next());    
                    } else {
                        break;
                    }
                }
                
                control = new PagedResultsRequestControl(pageSize, control.getCookie());
                
             } while (control.getCookie().getCookie() != null && (maxResults == -1 || shadowSecurityGroups.size() < maxResults));
            
        } catch (CommunicationException ce) {
            throw new InvalidConnectionException("getLdapGroups(): Could not connect to LDAP Server, error: " + ce.getMessage(), ce);
        } catch (org.springframework.ldap.AuthenticationException ae) {
            throw new InvalidCredentialsException("getLdapGroups(): Could not authenticate to LDAP, error: " + ae.getMessage(), ae);
        } catch (org.springframework.ldap.InvalidNameException ine) {
            throw new InvalidCredentialsException("getLdapGroups(): Could not authenticate to LDAP, error: " + ine.getMessage(), ine);                        
        } finally {
            Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
        
        Collections.sort(shadowSecurityGroups, new SecurityPrincipalComparator());
                
        return shadowSecurityGroups;
    }
    
    /*
     * 
     * @param usernameAttribute
     * @param emailAddressAttribute
     * @param firstNameAttribute
     * @param lastNameAttribute
     * @param multiTenancyRealm
     * @return
     */
    private ContextMapper buildShadowSecurityUserContextMapper(
        String usernameAttribute,
        String emailAddressAttribute,
        String firstNameAttribute,
        String lastNameAttribute,
        MultiTenancyRealm multiTenancyRealm) {
        
        int attributeCount = 4;
        if (emailAddressAttribute.trim().equals("")) {
            attributeCount = attributeCount - 1;
        }
        if (firstNameAttribute.trim().equals("")) {
            attributeCount = attributeCount - 1;
        }
        if (lastNameAttribute.trim().equals("")) {
            attributeCount = attributeCount - 1;
        }
        
        String[] attributeArray = new String[attributeCount];            
        attributeArray[0] = usernameAttribute;
        int i = 1;
        if (emailAddressAttribute.trim().equals("")) {
            attributeArray[i++] = emailAddressAttribute;
        }
        if (firstNameAttribute.trim().equals("")) {
            attributeArray[i++] = firstNameAttribute;
        }
        if (lastNameAttribute.trim().equals("")) {
            attributeArray[i++] = lastNameAttribute;
        }
        
        ContextMapper contextMapper = new ShadowSecurityUserContextMapper(
                usernameAttribute,
                emailAddressAttribute,
                firstNameAttribute,
                lastNameAttribute,
                multiTenancyRealm);
        
        return contextMapper;
    }

    /*
     * 
     * @param groupnameAttribute
     * @param descriptionAttribute
     * @param multiTenancyRealm
     * @return
     */
    private ContextMapper buildShadowSecurityGroupContextMapper(
        String groupnameAttribute,
        String groupDescriptionAttribute,
        MultiTenancyRealm multiTenancyRealm) {
        
        int attributeCount = 4;
        if (groupDescriptionAttribute.trim().equals("")) {
            attributeCount = attributeCount - 1;
        }
        String[] attributeArray = new String[attributeCount];            
        attributeArray[0] = groupnameAttribute;
        int i = 1;
        if (groupDescriptionAttribute.trim().equals("")) {
            attributeArray[i++] = groupDescriptionAttribute;
        }
        
        ContextMapper contextMapper = new ShadowSecurityGroupContextMapper(
                groupnameAttribute,
                groupDescriptionAttribute,
                multiTenancyRealm);
        
        return contextMapper;
    }    
}