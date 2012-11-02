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
public class DerbyJdbcConnectionStringBuilderStrategy extends AbstractJdbcConnectionStringBuilderStrategy{

    /**
     * 
     * @param hostname
     * @param port
     * @param databaseName
     * @param dbAuthType
     * @param additionalConnectionStringProperties
     * @throws ValidationException
     */
    public DerbyJdbcConnectionStringBuilderStrategy( 
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
        
        // jdbc:derby:cpwrSecurityDB;create=true
        sb.setLength(0);
        sb.append(IJdbcConfiguration.DERBY_CONNECTION_STRING_PREFIX);
        sb.append(this.databaseName);
        if (this.additionalConnectionStringProperties != null && this.additionalConnectionStringProperties.length() > 0) {
            
            sb.append(IJdbcConfiguration.SEMI_COLON_CHAR);
            sb.append(this.additionalConnectionStringProperties);
        }
        this.jdbcConnectionString = sb.toString();
        
        return this.jdbcConnectionString;
    }
    
    /*
     * 
     * @throws ValidationException
     */
    protected void validateHostname() throws ValidationException {
        if (this.hostname == null || this.hostname.trim().length() != 0) {
            throw new ValidationException(ValidationException.FIELD_HOST_NAME, ValidationException.REASON_MUST_BE_EMPTY);
        }        
    }
    
    /*
     * 
     * @throws ValidationException
     */
    protected void validatePort() throws ValidationException {
        if (this.port == null || this.port.trim().length() != 0) {
            throw new ValidationException(ValidationException.FIELD_PORT, ValidationException.REASON_MUST_BE_EMPTY);
        }        
    }
}