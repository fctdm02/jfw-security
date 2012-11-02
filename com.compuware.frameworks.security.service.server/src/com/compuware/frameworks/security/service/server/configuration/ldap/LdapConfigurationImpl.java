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
package com.compuware.frameworks.security.service.server.configuration.ldap;

import java.util.Map;

import com.compuware.frameworks.security.AbstractConfiguration;
import com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
public final class LdapConfigurationImpl extends AbstractConfiguration implements ILdapConfiguration {

    /**
     * 
     * @param ldapUrl
     * @return
     */
    public String parseEncryptionMethod(String ldapUrl) {
        
        if (ldapUrl.toLowerCase().startsWith(LDAP_URL_SSL_PROTOCOL_PREFIX)) {
            return LDAP_ENCRYPTION_METHOD_SSL;
        }
        
        return LDAP_ENCRYPTION_METHOD_NONE;
    }
    
    /**
     * 
     * @param ldapUrl
     * @return
     */
    public String parseHostname(String ldapUrl) {
        
        int firstColonIndex = ldapUrl.indexOf("://");
        int secondColonIndex = ldapUrl.indexOf(':', firstColonIndex+3);
        
        return ldapUrl.substring(firstColonIndex+3, secondColonIndex);
    }
    
    /**
     * 
     * @param ldapUrl
     * @return
     */
    public String parsePort(String ldapUrl) {
        
        String port = null;
        
        int firstColonIndex = ldapUrl.indexOf("://");
        int secondColonIndex = ldapUrl.indexOf(':', firstColonIndex+1);
                
        int secondForwardSlashIndex = ldapUrl.indexOf('/', secondColonIndex+1);
        if (secondForwardSlashIndex != -1) {
            port = ldapUrl.substring(secondColonIndex+1, secondForwardSlashIndex);
        } else {
            port = ldapUrl.substring(secondColonIndex+1);
        }
        
        return port;
    }
    
    /**
     * 
     * @param ldapUrl
     * @return
     */
    public String parseBaseDn(String ldapUrl) {
        
        String baseDn = null;
        
        int firstColonIndex = ldapUrl.indexOf("://");
        int secondColonIndex = ldapUrl.indexOf(':', firstColonIndex+1);
        
        int secondForwardSlashIndex = ldapUrl.indexOf('/', secondColonIndex+1);
        if (secondForwardSlashIndex != -1) {
            baseDn = ldapUrl.substring(secondForwardSlashIndex+1);    
        } else {
            baseDn = "";
        }
        
        return baseDn;
    }
    
    
    /**
     * @param configurationValues
     */
    public LdapConfigurationImpl(Map<String, String> configurationValues) {
        super(configurationValues);
    }

    
        
    public String getEnableLdapAuthentication() {
        return this.getConfigurationValue(ILdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY);        
    }
    
    public String getLdapType() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_TYPE_KEY);
    }
    
    public String getLdapUrl() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_URL_KEY);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration#getPerformServerCertificateValidation()
     */
    public boolean getPerformServerCertificateValidation() {
        String performServerCertificateValidation = this.getConfigurationValue(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY);
        if (performServerCertificateValidation != null && performServerCertificateValidation.trim().equalsIgnoreCase("true")) {
            return true;
        }
        return false;
    }
    
    // The following are convenience methods.
    public String getEncryptionMethod() {
        boolean useTls = getUseTls();
        if (useTls) {
            return ILdapConfiguration.LDAP_ENCRYPTION_METHOD_TLS;
        }
        String ldapUrl = getLdapUrl();
        return parseEncryptionMethod(ldapUrl);
    }
    public String getHostname() {        
        String ldapUrl = getLdapUrl();
        return parseHostname(ldapUrl);
    }
    public String getPort() {
        String ldapUrl = getLdapUrl();
        return parsePort(ldapUrl);
    }
    public String getBaseDn() {
        String ldapUrl = getLdapUrl();
        return parseBaseDn(ldapUrl);
    }
        
    public String getTimeout() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_TIMEOUT_KEY);
    }
    public String getPageSize() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_PAGE_SIZE_KEY);
    }

    public boolean getUseTls() {
        return Boolean.parseBoolean(this.getConfigurationValue(ILdapConfiguration.LDAP_USE_TLS_KEY));
    }
    
    public String getReferral() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_REFERRAL_KEY);
    }
    public String getReferralLimit() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY);
    }

    public String getServiceAccountUsername() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY);
    }
    public String getServiceAccountPassword() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY);
    }
    
    public String getGroupListSearchBase() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY);
    }
    public String getGroupListSearchFilter() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY);
    }
    public String getGroupGroupnameAttribute() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY);
    }
    public String getGroupDescriptionAttribute() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY);
    }
    
    public String getUserSearchBase() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY);
    }
    public String getUserSearchFilter() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY);
    }
    public String getUserUsernameAttribute() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY);
    }
    public String getUserEmailAddressAttribute() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY);
    }
    public String getUserFirstNameAttribute() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY);
    }
    public String getUserLastNameAttribute() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY);
    }
            
    public String getUserGroupsSearchBase() { // This isn't displayed in the Reporting portal UI.
        return this.getConfigurationValue(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY);
    }
    public String getUserGroupsSearchFilter() {
        return this.getConfigurationValue(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY);
    }
    
    
    
    
    
    public void setEnableLdapAuthentication(String enableLdapAuthentication) {
        this.setConfigurationValue(ILdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY, enableLdapAuthentication);   
    }
    
    public void setLdapType(String ldapType) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_TYPE_KEY, ldapType);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration#buildLdapUrl(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public String buildLdapUrl(
        String encryptionMethod,
        String hostname,
        String port,
        String baseDn) throws ValidationException {

        String ldapUrl = null;
        
        if (hostname == null || hostname.equals("")) {
            throw new ValidationException(ValidationException.FIELD_HOST_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
        }
        
        try {
            if (port == null || port.trim().equals("")) {
                throw new ValidationException(ValidationException.FIELD_PORT, ValidationException.REASON_CANNOT_BE_EMPTY);
            }
            int iPort = Integer.parseInt(port);
            if (iPort <= 0) {
                throw new ValidationException(ValidationException.FIELD_PORT, ValidationException.REASON_CANNOT_BE_NEGATIVE);
            }
        } catch (NumberFormatException nfe) {
            throw new ValidationException(ValidationException.FIELD_PORT, ValidationException.REASON_MUST_BE_A_VALID_NUMBER);
        }
        
        String protocol = null;
        if (encryptionMethod.equalsIgnoreCase(LDAP_ENCRYPTION_METHOD_NONE) || encryptionMethod.equalsIgnoreCase(LDAP_ENCRYPTION_METHOD_TLS)) {
            protocol = LDAP_URL_PLAIN_PROTOCOL_PREFIX;
        } else if (encryptionMethod.equalsIgnoreCase(LDAP_ENCRYPTION_METHOD_SSL)) {
            protocol = LDAP_URL_SSL_PROTOCOL_PREFIX;
        } else {
            String reason = ValidationException.REASON_INVALID_ENUMERATED_VALUE;
            reason = reason.replace(ValidationException.TOKEN_ZERO, encryptionMethod);
            reason = reason.replace(ValidationException.TOKEN_ONE, LDAP_ENCRYPTION_METHOD_NONE + ", " + LDAP_ENCRYPTION_METHOD_TLS + ", " + LDAP_ENCRYPTION_METHOD_SSL);
            throw new ValidationException(ValidationException.FIELD_ENCRYPTION_METHOD, reason);
        }
                
        if (baseDn != null && baseDn.length() > 0) {
            ldapUrl = protocol + "://" + hostname + ":" + port + "/" + baseDn;
        } else {
            ldapUrl = protocol + "://" + hostname + ":" + port;
        }
        
        return ldapUrl;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration#setLdapUrl(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public void setLdapUrl(
        String encryptionMethod,
        String hostname,
        String port,
        String baseDn) throws ValidationException {
        String ldapUrl = buildLdapUrl(encryptionMethod, hostname, port, baseDn);
        setLdapUrl(ldapUrl);
    }
    
    public void setLdapUrl(String ldapUrl) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_URL_KEY, ldapUrl);
    }
    
    public void setTimeout(String timeout) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_TIMEOUT_KEY, timeout);
    }
    public void setUseTls(String useTls) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_USE_TLS_KEY, useTls);
    }    
    public void setPageSize(String pageSize) { // This isn't displayed in the Reporting portal UI.
        this.setConfigurationValue(ILdapConfiguration.LDAP_PAGE_SIZE_KEY, pageSize);
    }
    
    public void setReferral(String referral) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_REFERRAL_KEY, referral);
    }
    public void setReferralLimit(String referralLimit) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY, referralLimit);
    }

    public void setServiceAccountUsername(String serviceAccountUsername) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY, serviceAccountUsername);
    }
    public void setServiceAccountPassword(String serviceAccountPassword) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY, serviceAccountPassword);
    }
    
    public void setGroupListSearchBase(String groupListSearchBase) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY, groupListSearchBase);
    }
    public void setGroupListSearchFilter(String groupListSearchFilter) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY, groupListSearchFilter);
    }
    public void setGroupGroupnameAttribute(String groupGroupnameAttribute) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY, groupGroupnameAttribute);
    }
    public void setGroupDescriptionAttribute(String groupDescriptionAttribute) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY, groupDescriptionAttribute);
    }
    
    public void setUserSearchBase(String userSearchBase) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY, userSearchBase);
    }
    public void setUserSearchFilter(String userSearchFilter) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY, userSearchFilter);
    }
    public void setUserUsernameAttribute(String userUsernameAttribute) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY, userUsernameAttribute);
    }
    public void setUserEmailAddressAttribute(String userEmailAddressAttribute) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY, userEmailAddressAttribute);
    }
    public void setUserFirstNameAttribute(String userFirstNameAttribute) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY, userFirstNameAttribute);
    }
    public void setUserLastNameAttribute(String userLastNameAttribute) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY, userLastNameAttribute);
    }
            
    public void setUserGroupsSearchBase(String userGroupsSearchBase) { // This isn't displayed in the Reporting portal UI.
        this.setConfigurationValue(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY, userGroupsSearchBase);
    }
    public void setUserGroupsSearchFilter(String userGroupsSearchFilter) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY, userGroupsSearchFilter);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration#setPerformServerCertificateValidation(boolean)
     */
    public void setPerformServerCertificateValidation(boolean performServerCertificateValidation) {
        this.setConfigurationValue(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY, Boolean.toString(performServerCertificateValidation));
    }
}