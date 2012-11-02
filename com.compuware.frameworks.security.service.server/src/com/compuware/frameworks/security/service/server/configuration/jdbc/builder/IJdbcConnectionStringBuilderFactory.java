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
package com.compuware.frameworks.security.service.server.configuration.jdbc.builder;

import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public interface IJdbcConnectionStringBuilderFactory {
    
    /**
     * Creates the appropriate JDBC connection string builder based upon <code>databaseType</code>.
     * 
     * @param databaseType Can be one of the constants defined in <code>IJdbcConfiguration</code>
     * <ol>
     *   <li>SQL Server</li>
     *   <li>Oracle</li>
     *   <li>Derby</li>
     * </ol>
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
     * @param additionalConnectionStringProperties Any additional name=value pairs (delimited by a semicolon) that is appended to the end
     *                   of the JDBC connection string (does not apply when the database type is DERBY)
     * @return
     * @throws ValidationException
     */
    IJdbcConnectionStringBuilderStrategy createJdbcConnectionStringBuilder(
        String databaseType,
        String hostname,        
        String port,
        String databaseName,
        String dbAuthType,
        String windowsDomain,
        String additionalConnectionStringProperties) throws ValidationException;
}