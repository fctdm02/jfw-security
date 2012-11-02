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
import com.compuware.frameworks.security.service.server.configuration.jdbc.AbstractJdbcConnectionString;

/**
 * 
 * @author tmyers
 */
public abstract class AbstractJdbcConnectionStringBuilderStrategy extends AbstractJdbcConnectionString implements IJdbcConnectionStringBuilderStrategy {
    
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
    public AbstractJdbcConnectionStringBuilderStrategy( 
        String hostname,        
        String port,
        String databaseName,
        String dbAuthType,
        String windowsDomain,
        String additionalConnectionStringProperties) throws ValidationException {
        
        super(hostname, port, databaseName, dbAuthType, windowsDomain, additionalConnectionStringProperties);
        validateFields();
        buildJdbcConnectionString();
    }           
}