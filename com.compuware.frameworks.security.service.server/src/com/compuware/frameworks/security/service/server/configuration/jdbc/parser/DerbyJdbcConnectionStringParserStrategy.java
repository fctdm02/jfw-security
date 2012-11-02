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
public class DerbyJdbcConnectionStringParserStrategy extends AbstractJdbcConnectionStringParserStrategy {

    /**
     * 
     * @param jdbcConnectionString
     */
    public DerbyJdbcConnectionStringParserStrategy( 
        String jdbcConnectionString) {
        super(jdbcConnectionString); 
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.server.configuration.jdbc.parser.AbstractJdbcConnectionStringParserStrategy#parseJdbcConnectionString()
     */
    protected void parseJdbcConnectionString() {
        
        //           1         2         3         4         5 
        // 012345678901234567890123456789012345678901234567890
        // jdbc:derby:cpwrSecurity;create=true
        if (this.jdbcConnectionString == null || this.jdbcConnectionString.isEmpty() || !this.jdbcConnectionString.startsWith(IJdbcConfiguration.DERBY_CONNECTION_STRING_PREFIX)) {
            throw new ServiceException("Invalid Derby JDBC Connection string: " + this.jdbcConnectionString);
        }
        
        int semiColonIndex = this.jdbcConnectionString.indexOf(IJdbcConfiguration.SEMI_COLON_CHAR);
        if (semiColonIndex != -1) {
            
            this.databaseName = this.jdbcConnectionString.substring(IJdbcConfiguration.DERBY_CONNECTION_STRING_PREFIX.length(), semiColonIndex);
            this.additionalConnectionStringProperties = this.jdbcConnectionString.substring(semiColonIndex + 1);
        } else {            
            this.databaseName = this.jdbcConnectionString.substring(IJdbcConfiguration.DERBY_CONNECTION_STRING_PREFIX.length());            
        }
    }
    
    /**
     * @return
     */
    public String getDatabaseType() {
        return IJdbcConfiguration.DERBY;        
    }
    
}