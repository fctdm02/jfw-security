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
package com.compuware.frameworks.security.service.server.configuration.jdbc.parser;

import com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration;
import com.compuware.frameworks.security.service.api.exception.ServiceException;

/**
 * 
 * @author tmyers
 */
public class JdbcConnectionStringParserFactory implements IJdbcConnectionStringParserFactory {

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.server.configuration.jdbc.parser.IJdbcConnectionStringParserFactory#createJdbcConnectionStringParser(java.lang.String)
     */
    public IJdbcConnectionStringParserStrategy createJdbcConnectionStringParser(String jdbcConnectionString) {
        
        if (jdbcConnectionString.contains(IJdbcConfiguration.SQLSERVER_CONNECTION_STRING_JDBC_PROTOCOL)) {              
            return new SqlServerJdbcConnectionStringParserStrategy(jdbcConnectionString);
            
        } else if (jdbcConnectionString.contains(IJdbcConfiguration.ORACLE_CONNECTION_STRING_JDBC_PROTOCOL)) {
            return new OracleJdbcConnectionStringParserStrategy(jdbcConnectionString);
            
        } else if (jdbcConnectionString.contains(IJdbcConfiguration.DERBY_CONNECTION_STRING_JDBC_PROTOCOL)) {            
            return new DerbyJdbcConnectionStringParserStrategy(jdbcConnectionString);
            
        } else {
            throw new ServiceException(
                IJdbcConfiguration.DATABASE_TYPE_EXCEPTION_MESSAGE_PREFIX 
                + jdbcConnectionString 
                + IJdbcConfiguration.DATABASE_TYPE_EXCEPTION_MESSAGE_SUFFIX);
        }
    }    
}