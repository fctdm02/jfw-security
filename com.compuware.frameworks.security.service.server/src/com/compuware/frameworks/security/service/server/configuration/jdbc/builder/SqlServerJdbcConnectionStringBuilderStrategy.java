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

import com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public class SqlServerJdbcConnectionStringBuilderStrategy extends AbstractJdbcConnectionStringBuilderStrategy{

    /**
     * 
     * @param hostname
     * @param port
     * @param databaseName
     * @param dbAuthType
     * @param windowsDomain
     * @param additionalConnectionStringProperties
     * @throws ValidationException
     */
    public SqlServerJdbcConnectionStringBuilderStrategy( 
        String hostname,        
        String port,
        String databaseName,
        String dbAuthType,
        String windowsDomain,
        String additionalConnectionStringProperties) throws ValidationException {
        super(hostname, port, databaseName, dbAuthType, windowsDomain, additionalConnectionStringProperties);
    }   

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.server.configuration.jdbc.builder.IJdbcConnectionStringBuilderStrategy#buildJdbcConnectionString()
     */
    public String buildJdbcConnectionString() {
        
        // jdbc:jtds:sqlserver://localhost:1433/cpwrSecurity
        sb.setLength(0);
        sb.append(IJdbcConfiguration.SQLSERVER_CONNECTION_STRING_PREFIX);
        sb.append(this.hostname);
        sb.append(IJdbcConfiguration.COLON_CHAR);
        sb.append(this.port);
        sb.append(IJdbcConfiguration.FORWARD_SLASH_CHAR);
        sb.append(this.databaseName);
        
        if (this.dbAuthType.equals(IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE)) { // We assume username/password are empty.
            sb.append(IJdbcConfiguration.SEMI_COLON_CHAR);
            sb.append(IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE_PROPERTY_KEY);
            sb.append(IJdbcConfiguration.EQUALS_CHAR);
            sb.append(IJdbcConfiguration.TRUE);
            
        } else if (this.dbAuthType.equals(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE)) {
            sb.append(IJdbcConfiguration.SEMI_COLON_CHAR);
            sb.append(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE_PROPERTY_KEY);
            sb.append(IJdbcConfiguration.EQUALS_CHAR);
            sb.append(this.windowsDomain);
            
        }
        
        if (this.additionalConnectionStringProperties != null && this.additionalConnectionStringProperties.length() > 0) {
            
            sb.append(IJdbcConfiguration.SEMI_COLON_CHAR);
            sb.append(this.additionalConnectionStringProperties);
        }
        this.jdbcConnectionString = sb.toString();
        
        return this.jdbcConnectionString;
    }
}