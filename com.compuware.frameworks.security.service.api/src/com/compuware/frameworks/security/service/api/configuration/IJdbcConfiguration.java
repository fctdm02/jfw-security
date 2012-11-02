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

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityJdbcConfiguration;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 *
 */
public interface IJdbcConfiguration extends ICompuwareSecurityJdbcConfiguration, IConfiguration {
                
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
    void setJdbcConfiguration(
            String databaseType,
            String hostname,
            String port,
            String databaseName,            
            String dbAuthType,
            String windowsDomain,
            String username,
            String password,
            String additionalConnectionStringProperties) throws ValidationException;

    /**
     * @return the <code>databaseType</code> for the currently set JDBC connection string.
     */
    String getDatabaseType();
    
    /**
     * @return the <code>hostname</code> for the currently set JDBC connection string.
     */
    String getHostname();
    
    /**
     * @return the <code>port</code> for the currently set JDBC connection string.
     */
    String getPort();
    
    /**
     * @return the <code>databaseName</code> for the currently set JDBC connection string.
     */
    String getDatabaseName();
    
    /**
     * @return an authentication type constant for the currently set JDBC connection string.
     * <p>
     * For non-windows/non-SQL Server the only choice is LOCAL_DB_AUTH_TYPE.  For windows, two additional
     * choices are: WINDOWS_DOMAIN_SQL_SERVER_AUTH_TYPE and INTEGRATED_SECURITY_SQL_SERVER_AUTH_TYPE
     */
    String getDbAuthType();
    
    /**
     *@return If WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE is used for the DB auth type, then the given
     *username/password will be authenticated against the windows domain specified by this field. 
     */
    String getWindowsDomain();
    
    /**
     * @return The service account username.  If the DB Auth Type is Integrated Security, this value will be
     * blank.  If DB Auth Type is Windows Domain authentication, then this value will represent the 
     * credentials for a windows domain account.
     */
    String getUsername();

    /**
     * @return The service account password.  If the DB Auth Type is Integrated Security, this value will be
     * blank.  If DB Auth Type is Windows Domain authentication, then this value will represent the 
     * credentials for a windows domain account.
     */
    String getPassword();
    
    /**
     * @return Any additional name=value pairs that are appended to the end of the connection string 
     * for the currently set JDBC connection string.
     */
    String getAdditionalConnectionStringProperties();        
}