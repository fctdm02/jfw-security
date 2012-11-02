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

import com.compuware.frameworks.security.service.server.configuration.jdbc.AbstractJdbcConnectionString;


/**
 * 
 * @author tmyers
 */
public abstract class AbstractJdbcConnectionStringParserStrategy extends AbstractJdbcConnectionString implements IJdbcConnectionStringParserStrategy {
    
    /**
     * 
     * @param jdbcConnectionString
     */
    public AbstractJdbcConnectionStringParserStrategy( 
        String jdbcConnectionString) {
        super(jdbcConnectionString); 
        parseJdbcConnectionString();        
    }
    
    /*
     * 
     */
    protected abstract void parseJdbcConnectionString();
}