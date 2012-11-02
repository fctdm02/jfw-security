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
package com.compuware.frameworks.security.service.api.configuration;

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityLdapConfiguration;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 *
 */
public interface ILdapConfiguration extends ICompuwareSecurityLdapConfiguration, IConfiguration {

    /**
     * 
     * @return
     */
    String getEnableLdapAuthentication();
    
    /**
     * 
     * @return
     */
    String getLdapType();
    
    /**
     * 
     * @return
     */
    String getLdapUrl();
    
    /**
     * 
     * @param ldapUrl
     * @return
     */
    String parseEncryptionMethod(String ldapUrl);
    
    /**
     * 
     * @param ldapUrl
     * @return
     */
    String parseHostname(String ldapUrl);
    
    /**
     * 
     * @param ldapUrl
     * @return
     */
    String parsePort(String ldapUrl);
    
    /**
     * 
     * @param ldapUrl
     * @return
     */
    String parseBaseDn(String ldapUrl);
    
    /**
     * 
     * @return
     */
    String getEncryptionMethod();
        
    /**
     * 
     * @return
     */
    String getHostname();
    
    /**
     * 
     * @return
     */
    String getPort();
    
    /**
     * 
     * @return
     */
    String getBaseDn();
    
    /**
     * 
     * @return
     */
    String getTimeout();
    
    /**
     * 
     * @return
     */
    String getPageSize();
    
    /**
     * Convenience method
     * 
     * @return
     */
    boolean getUseTls();
    
    /**
     * 
     * @return
     */
    boolean getPerformServerCertificateValidation();
     
    /**
     * 
     * @return
     */
    String getReferral();
    
    /**
     * 
     * @return
     */
    String getReferralLimit();

    /**
     * 
     * @return
     */
    String getServiceAccountUsername();
    
    /**
     * 
     * @return
     */
    String getServiceAccountPassword();
    
    /**
     * 
     * @return
     */
    String getGroupListSearchBase();
    
    /**
     * 
     * @return
     */
    String getGroupListSearchFilter();
    
    /**
     * 
     * @return
     */
    String getGroupGroupnameAttribute();
    
    /**
     * 
     * @return
     */
    String getGroupDescriptionAttribute();
    
    /**
     * 
     * @return
     */
    String getUserSearchBase();
    
    /**
     * 
     * @return
     */
    String getUserSearchFilter();
    
    /**
     * 
     * @return
     */
    String getUserUsernameAttribute();
    
    /**
     * 
     * @return
     */
    String getUserEmailAddressAttribute();
    
    /**
     * 
     * @return
     */
    String getUserFirstNameAttribute();
    
    /**
     * 
     * @return
     */
    String getUserLastNameAttribute();
       
    /**
     * 
     * @return
     */
    String getUserGroupsSearchBase();
    
    /**
     * 
     * @return
     */
    String getUserGroupsSearchFilter();
        
    /**
     * 
     * @param enableLdapAuthentication
     */
    void setEnableLdapAuthentication(String enableLdapAuthentication);
    
    /**
     * 
     * @param ldapType
     */
    void setLdapType(String ldapType);
    
    /**
     * 
     * @param ldapUrl
     */
    void setLdapUrl(String ldapUrl);
    
    /**
     * The following is to allow for the view layer to specify the components of the LDAP URL individually.
     * 
     * @param encryptionMethod
     * @param hostname
     * @param port
     * @param baseDn
     * @return
     * @throws ValidationException
     */
    String buildLdapUrl(
        String encryptionMethod,
        String hostname,
        String port,
        String baseDn) throws ValidationException;
    
    /**
     * 
     * @param encryptionMethod
     * @param hostname
     * @param port
     * @param baseDn
     * @throws ValidationException
     */
    void setLdapUrl(
            String encryptionMethod,
            String hostname,
            String port,
            String baseDn) throws ValidationException;
       
    /**
     * 
     * @param timeout
     */
    void setTimeout(String timeout);
    
    /**
     * 
     * @param pageSize
     */
    void setPageSize(String pageSize);
    
    /**
     * 
     * @param referral
     */
    void setReferral(String referral);
    
    /**
     * 
     * @param referralLimit
     */
    void setReferralLimit(String referralLimit);

    /**
     * 
     * @param serviceAccountUsername
     */
    void setServiceAccountUsername(String serviceAccountUsername);
    
    /**
     * 
     * @param serviceAccountPassword
     */
    void setServiceAccountPassword(String serviceAccountPassword);
    
    
    /**
     * 
     * @param groupListSearchBase
     */
    void setGroupListSearchBase(String groupListSearchBase);
    
    /**
     * 
     * @param groupListSearchFilter
     */
    void setGroupListSearchFilter(String groupListSearchFilter);
    
    /**
     * 
     * @param groupGroupnameAttribute
     */
    void setGroupGroupnameAttribute(String groupGroupnameAttribute);
    
    /**
     * 
     * @param groupDescriptionAttribute
     */
    void setGroupDescriptionAttribute(String groupDescriptionAttribute);
    
    /**
     * 
     * @param userSearchBase
     */
    void setUserSearchBase(String userSearchBase);
    
    /**
     * 
     * @param userSearchFilter
     */
    void setUserSearchFilter(String userSearchFilter);
    
    /**
     * 
     * @param userUsernameAttribute
     */
    void setUserUsernameAttribute(String userUsernameAttribute);
    
    /**
     * 
     * @param userEmailAddressAttribute
     */
    void setUserEmailAddressAttribute(String userEmailAddressAttribute);
    
    /**
     * 
     * @param userFirstNameAttribute
     */
    void setUserFirstNameAttribute(String userFirstNameAttribute);
    
    /**
     * 
     * @param userLastNameAttribute
     */
    void setUserLastNameAttribute(String userLastNameAttribute);
       
    /**
     * 
     * @param userGroupsSearchBase
     */
    void setUserGroupsSearchBase(String userGroupsSearchBase);
    
    /**
     * 
     * @param userGroupsSearchFilter
     */
    void setUserGroupsSearchFilter(String userGroupsSearchFilter);
    
    /**
     * 
     * @param performServerCertificateValidation
     */
    void setPerformServerCertificateValidation(boolean performServerCertificateValidation);
}