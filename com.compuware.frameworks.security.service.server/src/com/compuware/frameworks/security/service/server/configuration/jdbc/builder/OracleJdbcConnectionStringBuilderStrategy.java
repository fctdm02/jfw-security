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
public class OracleJdbcConnectionStringBuilderStrategy extends AbstractJdbcConnectionStringBuilderStrategy{

    /**
     * 
     * @param hostname
     * @param port
     * @param databaseName
     * @param dbAuthType
     * @param additionalConnectionStringProperties
     * @throws ValidationException
     */
    public OracleJdbcConnectionStringBuilderStrategy( 
        String hostname,        
        String port,
        String databaseName,
        String dbAuthType,
        String additionalConnectionStringProperties) throws ValidationException {
        super(hostname, port, databaseName, dbAuthType, "", additionalConnectionStringProperties);
    }   

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.server.configuration.jdbc.builder.IJdbcConnectionStringBuilderStrategy#buildJdbcConnectionString()
     */
    public String buildJdbcConnectionString() {
        
        // jdbc:oracle:thin:@localhost:1521:cpwrSecurity
        sb.setLength(0);
        sb.append(IJdbcConfiguration.ORACLE_CONNECTION_STRING_PREFIX);
        sb.append(this.hostname);
        sb.append(IJdbcConfiguration.COLON_CHAR);
        sb.append(this.port);
        sb.append(IJdbcConfiguration.COLON_CHAR);
        sb.append(this.databaseName);
        this.jdbcConnectionString = sb.toString();
        
        return this.jdbcConnectionString;
    }
}