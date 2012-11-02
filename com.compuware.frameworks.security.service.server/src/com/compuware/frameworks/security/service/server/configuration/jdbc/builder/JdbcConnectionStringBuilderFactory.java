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
import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public class JdbcConnectionStringBuilderFactory implements IJdbcConnectionStringBuilderFactory {
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.jdbc.builder.IJdbcConnectionStringBuilderFactory#createJdbcConnectionStringBuilder(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public IJdbcConnectionStringBuilderStrategy createJdbcConnectionStringBuilder(
        String databaseType,
        String hostname,        
        String port,
        String databaseName,
        String dbAuthType,
        String windowsDomain,
        String additionalConnectionStringProperties) throws ValidationException {
        
        if (databaseType.equals(IJdbcConfiguration.SQLSERVER)) {
            return new SqlServerJdbcConnectionStringBuilderStrategy(
                hostname,
                port,
                databaseName,
                dbAuthType,
                windowsDomain,
                additionalConnectionStringProperties);
            
        } else if (databaseType.equals(IJdbcConfiguration.ORACLE)) {
            return new OracleJdbcConnectionStringBuilderStrategy(
                hostname,
                port,
                databaseName,
                dbAuthType,
                additionalConnectionStringProperties);
            
        } else if (databaseType.equals(IJdbcConfiguration.DERBY)) {
            return new DerbyJdbcConnectionStringBuilderStrategy(
                hostname,
                port,
                databaseName,
                dbAuthType,
                additionalConnectionStringProperties);
            
        } else {
            throw new ServiceException(
                IJdbcConfiguration.DATABASE_TYPE_EXCEPTION_MESSAGE_PREFIX 
                + databaseType 
                + IJdbcConfiguration.DATABASE_TYPE_EXCEPTION_MESSAGE_SUFFIX);
        }                
    }
}