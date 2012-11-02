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
package com.compuware.frameworks.security.api.configuration;

/**
 * 
 * @author tmyers
 * <pre>
 ldap.configurationVersion=1
 ldap.userSearchBase=
 ldap.userLastNameAttribute=sn
 ldap.userUsernameAttribute=uid
 ldap.referralLimit=10
 ldap.groupDescriptionAttribute=description
 ldap.pageSize=1000
 ldap.groupListSearchBase=
 ldap.referral=follow
 ldap.userFirstNameAttribute=cn
 ldap.password=88cadd342b6dd56b2e5c8b646bfdb772
 ldap.enableLdapAuthentication=false
 ldap.groupListSearchFilter=(&(objectClass\=groupOfNames)({0}\={1}))
 ldap.userSearchFilter=(uid\={0})
 ldap.username=uid\=admin,ou\=system
 ldap.timeout=10000
 ldap.useTLS=false
 ldap.performServerCertificateValidation=false
 ldap.userEmailAddressAttribute=mail
 ldap.userGroupsSearchFilter=(member\={0})
 ldap.type=Apache DS
 ldap.url=ldap\://dtw-dev-css03\:10389/ou\=system
 ldap.userGroupsSearchBase=
 ldap.groupGroupnameAttribute=cn
 * </pre>
 *
 */
public interface ICompuwareSecurityLdapConfiguration  {

    /** */
    String APACHEDS = "Apache DS";
    
    /** */
    String ACTIVEDIR = "MS Active Directory";

    /** */
    String OTHER = "Other";
    
    
    /** */
    String LDAP_CONFIGURATION_VERSION_KEY = "ldap.configurationVersion";
    
    /** */
    String IS_LDAP_AUTHENTICATION_ENABLED_KEY = "ldap.isLdapAuthenticationEnabled";

    
    /** */
    String LDAP_TYPE_KEY = "ldap.type";
    
    /** */
    String LDAP_ENCRYPTION_METHOD_KEY = "ldap.encryptionMethod";
    /** */
    String LDAP_ENCRYPTION_METHOD_NONE = "None";
    /** */
    String LDAP_ENCRYPTION_METHOD_SSL = "SSL";
    /** */
    String LDAP_ENCRYPTION_METHOD_TLS = "TLS";    
    /** */
    String LDAP_URL_PLAIN_PROTOCOL_PREFIX = "ldap";    
    /** */
    String LDAP_URL_SSL_PROTOCOL_PREFIX = "ldaps";

    
    /** */
    String LDAP_REFERRAL_FOLLOW = "follow";
    /** */
    String LDAP_REFERRAL_IGNORE = "ignore";
    /** */
    String LDAP_REFERRAL_THROW = "throw";
    
    
    /** */
    String LDAP_URL_KEY = "ldap.url";
    /** */
    String LDAP_SERVICE_ACCOUNT_USERNAME_KEY = "ldap.username";
    /** */
    String LDAP_SERVICE_ACCOUNT_PASSWORD_KEY = "ldap.password";
    /** */
    String LDAP_SERVICE_ACCOUNT_CLEAR_TEXT_FLAG_KEY = "ldap.passwordcleartext";    
    /** */
    String LDAP_REFERRAL_KEY = "ldap.referral";
    /** */
    String LDAP_REFERRAL_LIMIT_KEY = "ldap.referralLimit";
    /** */
    String LDAP_TIMEOUT_KEY = "ldap.timeout";
    /** */
    String LDAP_USE_TLS_KEY = "ldap.useTLS";
    /** */
    String LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY = "ldap.performServerCertificateValidation";        
    /** */
    String LDAP_PAGE_SIZE_KEY = "ldap.pageSize";
    /** */
    String LDAP_USER_USERNAME_ATTRIBUTE_KEY = "ldap.userUsernameAttribute";
    /** */
    String LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY = "ldap.userEmailAddressAttribute";
    /** */
    String LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY = "ldap.userFirstNameAttribute";
    /** */
    String LDAP_USER_LAST_NAME_ATTRIBUTE_KEY = "ldap.userLastNameAttribute";
    /** */
    String LDAP_USER_SEARCH_BASE_KEY = "ldap.userSearchBase";
    /** */
    String LDAP_USER_SEARCH_FILTER_KEY = "ldap.userSearchFilter";
    /** */
    String LDAP_USER_GROUPS_SEARCH_BASE_KEY = "ldap.userGroupsSearchBase";
    /** */
    String LDAP_USER_GROUPS_SEARCH_FILTER_KEY = "ldap.userGroupsSearchFilter";
    /** */
    String LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY = "ldap.groupGroupnameAttribute";
    /** */
    String LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY = "ldap.groupDescriptionAttribute";
    /** */
    String LDAP_GROUP_LIST_SEARCH_BASE_KEY = "ldap.groupListSearchBase";
    /** */
    String LDAP_GROUP_LIST_SEARCH_FILTER_KEY = "ldap.groupListSearchFilter";

    
    /** */
    String DEFAULT_LDAP_CONFIGURATION_VERSION_VALUE = "1";    
    /** */
    String DEFAULT_IS_LDAP_AUTHENTICATION_ENABLED_VALUE = "false";
    /** */
    String DEFAULT_TYPE_VALUE = APACHEDS;        
    /** */
    String DEFAULT_LDAP_REFERRAL_VALUE = LDAP_REFERRAL_FOLLOW;
    /** */
    String DEFAULT_LDAP_REFERRAL_LIMIT_VALUE = "10";
    /** 
     * The JNDI LDAP timeout is in milliseconds, see: <br>
     * <a href="http://download.oracle.com/javase/jndi/tutorial/ldap/index.html">Tips for LDAP Users</a>
     */
    String DEFAULT_LDAP_TIMEOUT_VALUE = "10000";
    /** */
    String DEFAULT_LDAP_USE_TLS_VALUE = "false";
    /** */
    String DEFAULT_LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_VALUE = "false";    
    /** */
    String DEFAULT_LDAP_PAGE_SIZE_VALUE = "1000";
    
    
    /** */
    String DEFAULT_LDAP_APACHEDS_URL_VALUE = "ldap://localhost:10389/ou=system";
    /** */
    String DEFAULT_LDAP_APACHEDS_SERVICE_ACCOUNT_USERNAME_VALUE = "uid=admin,ou=system";
    /** */
    String DEFAULT_LDAP_APACHEDS_SERVICE_ACCOUNT_PASSWORD_VALUE = "secret";
    /** */
    String DEFAULT_LDAP_APACHEDS_USER_USERNAME_ATTRIBUTE_VALUE = "uid";
    /** */
    String DEFAULT_LDAP_APACHEDS_USER_EMAIL_ADDRESS_ATTRIBUTE_VALUE = "mail";
    /** */
    String DEFAULT_LDAP_APACHEDS_USER_FIRST_NAME_ATTRIBUTE_VALUE = "cn";
    /** */
    String DEFAULT_LDAP_APACHEDS_USER_LAST_NAME_ATTRIBUTE_VALUE = "sn";
    /** */
    String DEFAULT_LDAP_APACHEDS_USER_SEARCH_BASE_VALUE = "";
    /** */
    String DEFAULT_LDAP_APACHEDS_USER_SEARCH_FILTER_VALUE = "(uid={0})";
    /** */
    String DEFAULT_LDAP_APACHEDS_USER_GROUPS_SEARCH_BASE_VALUE = "";
    /** */
    String DEFAULT_LDAP_APACHEDS_USER_GROUPS_SEARCH_FILTER_VALUE = "(member={0})";
    /** */
    String DEFAULT_LDAP_APACHEDS_GROUP_GROUPNAME_ATTRIBUTE_VALUE = "cn";
    /** */
    String DEFAULT_LDAP_APACHEDS_GROUP_DESCRIPTION_ATTRIBUTE_VALUE = "description";
    /** */
    String DEFAULT_LDAP_APACHEDS_GROUP_LIST_SEARCH_BASE_VALUE = "";
    /** */
    String DEFAULT_LDAP_APACHEDS_GROUP_LIST_SEARCH_FILTER_VALUE = "(&(objectClass=groupOfNames)({0}={1}))";
    
    
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_LDAP_TYPE_VALUE = ACTIVEDIR;        
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_URL_VALUE = "ldaps://localhost:636";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_SERVICE_ACCOUNT_USERNAME_VALUE = "";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_SERVICE_ACCOUNT_PASSWORD_VALUE = "";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_USER_USERNAME_ATTRIBUTE_VALUE = "sAMAccountName";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_USER_EMAIL_ADDRESS_ATTRIBUTE_VALUE = "mail";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_USER_FIRST_NAME_ATTRIBUTE_VALUE = "givenName";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_USER_LAST_NAME_ATTRIBUTE_VALUE = "sn";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_USER_SEARCH_BASE_VALUE = "";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_USER_SEARCH_FILTER_VALUE = "(&(sAMAccountName={0})(objectClass=user))";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_USER_GROUPS_SEARCH_BASE_VALUE = "";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_USER_GROUPS_SEARCH_FILTER_VALUE = "(member={0})";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_GROUP_GROUPNAME_ATTRIBUTE_VALUE = "cn";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_GROUP_DESCRIPTION_ATTRIBUTE_VALUE = "description";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_GROUP_LIST_SEARCH_BASE_VALUE = "";
    /** */
    String DEFAULT_LDAP_ACTIVEDIR_GROUP_LIST_SEARCH_FILTER_VALUE = "(&(objectClass=group)({0}={1}))";
}