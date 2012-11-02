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
package com.compuware.frameworks.security.service.server.configuration.jdbc;

import com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;


/**
 * 
 * @author tmyers
 */
public abstract class AbstractJdbcConnectionString {
    
    // This is used by both the builders and parsers.
    protected StringBuilder sb = new StringBuilder();
    
    
    // This is set by the builders.
    /* */
    protected String jdbcConnectionString = "";
    
    

    // These are set by the parsers.
    /* */
    protected String hostname = "";
    
    /* */
    protected String port = "";
    
    /* */
    protected String databaseName = "";
    
    /* */
    protected String dbAuthType = IJdbcConfiguration.LOCAL_DB_AUTH_TYPE;
    
    /* */
    protected String windowsDomain = ""; // Only has meaning when dbAuthTYpe is WINDOWS_DOMAIN_DB_AUTH_TYPE 
    
    /* */
    protected String additionalConnectionStringProperties = "";
    
    
    
    /**
     * 
     * @param jdbcConnectionString
     */
    public AbstractJdbcConnectionString(String jdbcConnectionString) {
        this.jdbcConnectionString = jdbcConnectionString;
    }   
    
    /**
     * 
     * @param hostname
     * @param port
     * @param databaseName
     * @param dbAuthType
     * @param windowsDomain
     * @param additionalConnectionStringProperties
     */
    public AbstractJdbcConnectionString( 
        String hostname,        
        String port,
        String databaseName,
        String dbAuthType,
        String windowsDomain,
        String additionalConnectionStringProperties) {
        this.hostname = hostname;
        if (this.hostname != null) {
            this.hostname = this.hostname.trim();
        }
        this.port = port;
        if (this.port != null) {
            this.port = this.port.trim();
        }
        this.databaseName = databaseName;
        if (this.databaseName != null) {
            this.databaseName = this.databaseName.trim();
        }        
        this.dbAuthType = dbAuthType;
        this.windowsDomain = windowsDomain;
        if (this.windowsDomain != null) {
            this.windowsDomain = this.windowsDomain.trim();
        }                
        this.additionalConnectionStringProperties = additionalConnectionStringProperties;
        if (this.additionalConnectionStringProperties != null) {
            this.additionalConnectionStringProperties = this.additionalConnectionStringProperties.trim();
        }        
    }           
    
    /**
     * @return
     */
    public String getJdbcConnectionString() {
        return this.jdbcConnectionString;
    }
            
    /**
     * @return
     */
    public String getHostname() {
        return this.hostname;
    }
    
    /**
     * @return
     */
    public String getPort() {
        return this.port;
    }
    
    /**
     * @return
     */
    public String getDatabaseName() {
        return this.databaseName;
    }
    
    /**
     * @return
     */
    public String getDbAuthType() {
        return this.dbAuthType;
    }
    
    /**
     *
     * @return
     */
    public String getWindowsDomain() {
        return this.windowsDomain;
    }
    
    /**
     * @return
     */
    public String getAdditionalConnectionStringProperties() {
        return this.additionalConnectionStringProperties;
    }
    
    /*
     * 
     * @throws ValidationException
     */
    protected void validateFields() throws ValidationException {
        validateHostname();
        validatePort();
        validateDatabaseName();
    }

    /*
     * 
     * @throws ValidationException
     */
    protected void validateHostname() throws ValidationException {
        if (this.hostname == null || this.hostname.trim().length() == 0) {
            throw new ValidationException(ValidationException.FIELD_HOST_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
        }
    }
    
    /*
     * 
     * @throws ValidationException
     */
    protected void validatePort() throws ValidationException {
        if (this.port == null || this.port.trim().length() == 0) {
            throw new ValidationException(ValidationException.FIELD_PORT, ValidationException.REASON_CANNOT_BE_EMPTY);
        }        
        if (this.port.startsWith("-")) {
            throw new ValidationException(ValidationException.FIELD_PORT, ValidationException.REASON_CANNOT_BE_NEGATIVE);
        }
        if (this.port.contains(".")) {
            throw new ValidationException(ValidationException.FIELD_PORT, ValidationException.REASON_MUST_BE_A_INTEGRAL_NUMBER);
        }        
        try {
            Integer.parseInt(this.port);
        } catch (NumberFormatException nfe) {
            throw new ValidationException(ValidationException.FIELD_PORT, ValidationException.REASON_MUST_BE_A_VALID_NUMBER);
        }
    }
    
    /*
     * 
     * @throws ValidationException
     */
    protected void validateDatabaseName() throws ValidationException {
        if (this.databaseName == null || this.databaseName.trim().length() == 0) {
            throw new ValidationException(ValidationException.FIELD_DATABASE_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
        }
    }
}