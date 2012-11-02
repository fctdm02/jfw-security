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
public class OracleJdbcConnectionStringParserStrategy extends AbstractJdbcConnectionStringParserStrategy {

    /**
     * 
     * @param jdbcConnectionString
     */
    public OracleJdbcConnectionStringParserStrategy( 
        String jdbcConnectionString) {
        super(jdbcConnectionString); 
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.server.configuration.jdbc.parser.AbstractJdbcConnectionStringParserStrategy#parseJdbcConnectionString()
     */
    protected void parseJdbcConnectionString() {
        
        // jdbc:oracle:thin:@localhost:1521:cpwrSecurity
        if (this.jdbcConnectionString == null || this.jdbcConnectionString.isEmpty() || !this.jdbcConnectionString.startsWith(IJdbcConfiguration.ORACLE_CONNECTION_STRING_PREFIX)) {
            throw new ServiceException("Invalid Oracle JDBC Connection string: " + this.jdbcConnectionString);
        }
        
        int firstColonIndex = this.jdbcConnectionString.indexOf(IJdbcConfiguration.COLON_CHAR, IJdbcConfiguration.ORACLE_CONNECTION_STRING_PREFIX.length() + 1);
        if (firstColonIndex != -1) {

            this.hostname = this.jdbcConnectionString.substring(IJdbcConfiguration.ORACLE_CONNECTION_STRING_PREFIX.length(), firstColonIndex);
            
            int secondColonIndex = this.jdbcConnectionString.indexOf(IJdbcConfiguration.COLON_CHAR, firstColonIndex + 1);
            if (secondColonIndex != -1) {

                this.port = this.jdbcConnectionString.substring(firstColonIndex + 1, secondColonIndex);
                
                int semiColonIndex = this.jdbcConnectionString.indexOf(IJdbcConfiguration.SEMI_COLON_CHAR);
                if (semiColonIndex != -1) {
                    
                    this.databaseName = this.jdbcConnectionString.substring(secondColonIndex + 1, semiColonIndex);
                    this.additionalConnectionStringProperties = this.jdbcConnectionString.substring(semiColonIndex + 1);
                } else {
                    this.databaseName = this.jdbcConnectionString.substring(secondColonIndex + 1);
                }
            }
        }
    }
    
    /**
     * @return
     */
    public String getDatabaseType() {
        return IJdbcConfiguration.ORACLE;        
    }
}