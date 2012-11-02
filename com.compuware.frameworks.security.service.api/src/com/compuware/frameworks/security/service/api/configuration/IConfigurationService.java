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

import java.util.List;
import java.util.Map;

import org.springframework.security.access.annotation.Secured;

import com.compuware.frameworks.security.service.api.configuration.exception.ConfigurationException;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 *
 */
public interface IConfigurationService {

    /** */
    String OS_ARCH_SYSTEM_PROPERTY = "os.arch";

    /** */
    String OS_NAME_SYSTEM_PROPERTY = "os.name";
    
    /** */
    String OS_VERSION_SYSTEM_PROPERTY = "os.version";

    /** */
    String JVM_VENDOR_SYSTEM_PROPERTY = "java.vm.vendor";

    /** */
    String JVM_NAME_SYSTEM_PROPERTY = "java.vm.name";

    /** */
    String JVM_VERSION_SYSTEM_PROPERTY = "java.vm.version";
    
    
    /** */
    String OS_NAME_WINDOWS = "Windows";
    
    /**
     * 
     * @return Map<String, String>
     */
    Map<String, String> getDefaultJdbcConfiguration();
    
    /**
     * 
     * @return Map<String, String>
     */
    Map<String, String> getDefaultEmbeddedDerbyJdbcConfiguration();
    
    /**
     * 
     * @return Map<String, String>
     */
    Map<String, String> getDefaultSqlServerJdbcConfiguration();
        
    /**
     * 
     * @return IJdbcConfiguration
     */
    IJdbcConfiguration getJdbcConfiguration();

    
    
    /**
     * 
     * @return Map<String, String>
     */
    Map<String, String> getDefaultLdapConfiguration();

    /**
     * 
     * @return Map<String, String>
     */
    Map<String, String> getDefaultApacheDsLdapConfiguration();

    /**
     * 
     * @return Map<String, String>
     */
    Map<String, String> getDefaultActiveDirectoryLdapConfiguration();
    
    /**
     * 
     * @return ILdapConfiguration
     */
    ILdapConfiguration getLdapConfiguration();
    
    

    /**
     * @param ldapConfiguration
     * @throws ValidationException
     * @throws ConfigurationException
     */
    @Secured({IManagementService.JFW_SEC_CONFIG_ROLENAME})
    void storeConfiguration(ILdapConfiguration ldapConfiguration) 
    throws 
        ValidationException, 
        ConfigurationException;

    /**
     * @param jdbcConfiguration
     * @throws ValidationException
     * @throws ConfigurationException
     */
    @Secured({IManagementService.JFW_SEC_CONFIG_ROLENAME})
    void storeConfiguration(IJdbcConfiguration jdbcConfiguration) 
    throws 
        ValidationException, 
        ConfigurationException;
    
    /**
     * @param ldapConfiguration
     * @param jdbcConfiguration
     * @throws ValidationException
     * @throws ConfigurationException
     */
    @Secured({IManagementService.JFW_SEC_CONFIG_ROLENAME})
    void storeConfiguration(
        ILdapConfiguration ldapConfiguration,
        IJdbcConfiguration jdbcConfiguration) 
    throws 
        ValidationException, 
        ConfigurationException;
    
    /**
     * 
     * @return the value of the <code>os.name</code> System Property, as retrieved on the 
     * server.
     */
    String getSecurityServerOperatingSystemName();
        
    /**
     * 
     * @return The list of supported database type constants.
     * <p>
     * @see IJdbcConfiguration.SQLSERVER
     * @see IJdbcConfiguration.ORACLE
     * @see IJdbcConfiguration.DERBY
     */
    List<String> getSupportedDatabaseTypes();
    
    /**
     * 
     * @param databaseType
     * 
     * @return Given the operating system that the server is running on <b>and</b>
     * <code>databaseType</code>, the list of supported DB authentication methods.
     * <p>
     * @see getSecurityServerOperatingSystemName()
     * @see getSuportedDatabaseTypes()
     * 
     * @see IJdbcConfiguration.LOCAL_DB_AUTH_TYPE - (default) Can be used for any 
     * server operating system/database type combination.  Username/password refer
     * to credentials stored in the database.
     * 
     * @see IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE - Can only be
     * used with the Windows/SQL Server operating system/database type combination.
     * username/password fields are ignored, as the driver will use the credentials
     * of the logged in user automatically.
     * 
     * @see IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE - Can only be
     * used with the Windows/SQL Server operating system/database type combination.
     * username/password fields refer to credentials of an account specified by the
     * <code>windowsDomain</code> field. 
     */
    List<String> getSupportedDatabaseAuthenticationTypes(String databaseType);   

	/**
	 * 
	 * @return The list of supported constants for Ldap encryption methods.
	 */
	List<String> getSupportedLdapEncryptionMethods();

	/**
	 * 
	 * @return The list of supported constants for LDAP implementations.
	 */
	List<String> getSupportedLdapDirectories();
	
    /**
     * 
     * @return The following system properties:
     * <ul>
     * <li><code>os.arch</code></li>
     * <li><code>os.name</code></li>
     * <li><code>os.version</code></li>
     * </ul>
     *  as retrieved on the computer running the security server.
     */
    String getSecurityServerOperatingSystemInfo();

    /**
     * 
     * @return The following system properties:
     * <ul>
     * <li><code>java.vm.vendor</code></li>
     * <li><code>java.vm.name</code></li>
     * <li><code>java.vm.version</code></li>
     * </ul>
     *  as retrieved on the computer running the security server.
     */
    String getSecurityServerJavaVirtualMachineInfo();
    
    /**
     * 
     * @return The following properties:
     * <ul>
     * <li><code>serviceDisplay</code></li>
     * <li><code>version</code></li>
     * <li><code>build</code></li>
     * </ul>
     *  as retrieved from the installation directory (i.e. the parent
     *  directory to the "osgi.instance.area") from the 
     *  Compuware Release Engineering <b>version.xml</b> running the 
     *  security server.
     *  <p>
     *  For example:
     *  <pre>
     *  Compuware Security Server - version 5.2.0 - build 342
     *  </pre>
     */
    String getSecurityServerReleaseInformation();
}