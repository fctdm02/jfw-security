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

import java.util.Map;

import org.apache.log4j.Logger;

import com.compuware.frameworks.security.AbstractConfiguration;
import com.compuware.frameworks.security.service.api.configuration.IConfigurationService;
import com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;
import com.compuware.frameworks.security.service.server.configuration.jdbc.builder.IJdbcConnectionStringBuilderFactory;
import com.compuware.frameworks.security.service.server.configuration.jdbc.builder.IJdbcConnectionStringBuilderStrategy;
import com.compuware.frameworks.security.service.server.configuration.jdbc.builder.JdbcConnectionStringBuilderFactory;
import com.compuware.frameworks.security.service.server.configuration.jdbc.parser.IJdbcConnectionStringParserFactory;
import com.compuware.frameworks.security.service.server.configuration.jdbc.parser.IJdbcConnectionStringParserStrategy;
import com.compuware.frameworks.security.service.server.configuration.jdbc.parser.JdbcConnectionStringParserFactory;

/**
 *  
 * @author tmyers
 */
public final class JdbcConfigurationImpl extends AbstractConfiguration implements IJdbcConfiguration {

    /* */
    private final IJdbcConnectionStringParserFactory jdbcConnectionStringParserFactory = new JdbcConnectionStringParserFactory();

    /* */
    private final IJdbcConnectionStringBuilderFactory jdbcConnectionStringBuilderFactory = new JdbcConnectionStringBuilderFactory();
    
    /* */
    private IJdbcConnectionStringParserStrategy jdbcConnectionStringParserStrategy;
    
    /* */
    private IJdbcConnectionStringBuilderStrategy jdbcConnectionStringBuilderStrategy;
    

    /* */
    private final Logger logger = Logger.getLogger(JdbcConfigurationImpl.class);
    
    /**
     * @param configurationValues
     */
    public JdbcConfigurationImpl(Map<String, String> configurationValues) {
        super(configurationValues);
        
        String jdbcConnectionString = this.getConfigurationValue(IJdbcConfiguration.JDBC_CONNECTION_STRING_KEY);
        this.jdbcConnectionStringParserStrategy = this.jdbcConnectionStringParserFactory.createJdbcConnectionStringParser(jdbcConnectionString); 
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.AbstractConfiguration#setConfigurationValue(java.lang.String, java.lang.String)
     */
    public void setConfigurationValue(String key, String value) {

        super.setConfigurationValue(key, value);
        if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_CONNECTION_STRING_KEY)) {
            
            this.jdbcConnectionStringParserStrategy = this.jdbcConnectionStringParserFactory.createJdbcConnectionStringParser(value);
     
            String databaseType = this.jdbcConnectionStringParserStrategy.getDatabaseType(); 
            String dbAuthType = this.jdbcConnectionStringParserStrategy.getDbAuthType();
            
            setDerivedProperties(databaseType, dbAuthType);
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#setJdbcConfiguration(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public void setJdbcConfiguration(
            String databaseType,
            String hostname,
            String port,
            String databaseName,            
            String dbAuthType,
            String windowsDomain,
            String username,
            String password,
            String additionalConnectionStringProperties) throws ValidationException {
                
        if (!databaseType.equals(IJdbcConfiguration.SQLSERVER) 
            && !databaseType.equals(IJdbcConfiguration.ORACLE) 
            && !databaseType.equals(IJdbcConfiguration.DERBY)) {
            
            String reason = ValidationException.REASON_INVALID_ENUMERATED_VALUE;
            reason = reason.replace(ValidationException.TOKEN_ZERO, databaseType);
            reason = reason.replace(ValidationException.TOKEN_ONE, IJdbcConfiguration.SQLSERVER + ", " + IJdbcConfiguration.ORACLE + ", " + IJdbcConfiguration.DERBY);
            throw new ValidationException(ValidationException.FIELD_DATABASE_TYPE,  reason);
        }
                            
        String osName = System.getProperty(IConfigurationService.OS_NAME_SYSTEM_PROPERTY);
        if (osName.startsWith(IConfigurationService.OS_NAME_WINDOWS)) {
            if (dbAuthType.equals(IJdbcConfiguration.LOCAL_DB_AUTH_TYPE) || dbAuthType.equals(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE)) {
                validateUsername(username);
                validatePassword(password);
                if (dbAuthType.equals(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE) && (windowsDomain == null || windowsDomain.equals(""))) {
                    throw new ValidationException(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE_PROPERTY_KEY, ValidationException.REASON_CANNOT_BE_EMPTY);
                }
            } else if (dbAuthType.equals(IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE)) {
                if (username != null && !username.equals("")) {
                    throw new ValidationException(ValidationException.FIELD_USERNAME, ValidationException.REASON_MUST_BE_EMPTY);
                }
                if (password != null && !password.equals("")) {
                    throw new ValidationException(ValidationException.FIELD_PASSWORD, ValidationException.REASON_MUST_BE_EMPTY);
                }                
            } else  {
                String reason = ValidationException.REASON_INVALID_ENUMERATED_VALUE;
                reason = reason.replace(ValidationException.TOKEN_ZERO, dbAuthType);
                reason = reason.replace(ValidationException.TOKEN_ONE, IJdbcConfiguration.LOCAL_DB_AUTH_TYPE + ", " + IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE + ", " + IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE);
                throw new ValidationException(ValidationException.FIELD_DATABASE_AUTHORIZATION_TYPE,  reason);
            }
        } else {
            if (dbAuthType.equals(IJdbcConfiguration.LOCAL_DB_AUTH_TYPE)) {
                validateUsername(username);
                validatePassword(password);
            } else {
                String reason = ValidationException.REASON_INVALID_ENUMERATED_VALUE;
                reason = reason.replace(ValidationException.TOKEN_ZERO, dbAuthType);
                reason = reason.replace(ValidationException.TOKEN_ONE, IJdbcConfiguration.LOCAL_DB_AUTH_TYPE);
                throw new ValidationException(ValidationException.FIELD_DATABASE_AUTHORIZATION_TYPE,  reason);
            }
        }
        
        this.jdbcConnectionStringBuilderStrategy = this.jdbcConnectionStringBuilderFactory.createJdbcConnectionStringBuilder(
                databaseType, 
                hostname, 
                port, 
                databaseName, 
                dbAuthType, 
                windowsDomain, 
                additionalConnectionStringProperties);
                
        String jdbcConnectionString = this.jdbcConnectionStringBuilderStrategy.buildJdbcConnectionString();
        super.setConfigurationValue(IJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, jdbcConnectionString);
        super.setConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, username);
        super.setConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, password);
        
        setDerivedProperties(databaseType, dbAuthType);
        
        String driverClassName = super.getConfigurationValue(IJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY);
        String adjusedUsername = super.getConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY);
        
        StringBuilder sb = new StringBuilder();        
        sb.append("Setting JDBC Configuration to type: ");
        sb.append(databaseType);
        sb.append(", using driverClassName: ");
        sb.append(driverClassName);
        sb.append(", jdbcConnectionString: ");
        sb.append(jdbcConnectionString);
        sb.append(", dbAuthType: ");
        sb.append(dbAuthType);
        sb.append(" and  username: ");
        sb.append(adjusedUsername);
        logger.debug(sb.toString());
    }
    
    /*
     * 
     * @param databaseType
     * @param dbAuthType
     */
    private void setDerivedProperties(String databaseType, String dbAuthType) {

        // Set the corresponding properties given the given database type.
        if (databaseType.equals(IJdbcConfiguration.SQLSERVER)) {
            super.setConfigurationValue(IJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_DRIVER_CLASS_NAME_VALUE);
            super.setConfigurationValue(IJdbcConfiguration.HIBERNATE_DIALECT_KEY, IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_HIBERNATE_DIALECT_VALUE);
            super.setConfigurationValue(IJdbcConfiguration.JDBC_SQL_DIALECT_KEY, IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_SQL_DIALECT_VALUE);
                        
        } else if (databaseType.equals(IJdbcConfiguration.ORACLE)) {
            super.setConfigurationValue(IJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, IJdbcConfiguration.DEFAULT_JDBC_ORACLE_DRIVER_CLASS_NAME_VALUE);
            super.setConfigurationValue(IJdbcConfiguration.HIBERNATE_DIALECT_KEY, IJdbcConfiguration.DEFAULT_JDBC_ORACLE_HIBERNATE_DIALECT_VALUE);
            super.setConfigurationValue(IJdbcConfiguration.JDBC_SQL_DIALECT_KEY, IJdbcConfiguration.DEFAULT_JDBC_ORACLE_SQL_DIALECT_VALUE);
            
        } else {
            super.setConfigurationValue(IJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, IJdbcConfiguration.DEFAULT_JDBC_DERBY_DRIVER_CLASS_NAME_VALUE);
            super.setConfigurationValue(IJdbcConfiguration.HIBERNATE_DIALECT_KEY, IJdbcConfiguration.DEFAULT_JDBC_DERBY_HIBERNATE_DIALECT_VALUE);
            super.setConfigurationValue(IJdbcConfiguration.JDBC_SQL_DIALECT_KEY, IJdbcConfiguration.DEFAULT_JDBC_DERBY_SQL_DIALECT_VALUE);
        }
        
        // If we are using Windows Integrated Security, then we need to clear the username/password fields.
        if (dbAuthType.equals(IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE)) {
            super.setConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, "");
            super.setConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, "");
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getDatabaseType()
     */
    public String getDatabaseType() {
        return this.jdbcConnectionStringParserStrategy.getDatabaseType();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getHostname()
     */
    public String getHostname() {
        return this.jdbcConnectionStringParserStrategy.getHostname();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getPort()
     */
    public String getPort() {
        return this.jdbcConnectionStringParserStrategy.getPort();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getDatabaseName()
     */
    public String getDatabaseName() {
        return this.jdbcConnectionStringParserStrategy.getDatabaseName();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getDbAuthType()
     */
    public String getDbAuthType() {
        return this.jdbcConnectionStringParserStrategy.getDbAuthType();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getWindowsDomain()
     */
    public String getWindowsDomain() {
        return this.jdbcConnectionStringParserStrategy.getWindowsDomain();
    }
 
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getUsername()
     */
    public String getUsername() {
        return this.getConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getPassword()
     */
    public String getPassword() {
        return this.getConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration#getAdditionalConnectionStringProperties()
     */
    public String getAdditionalConnectionStringProperties() {
        return this.jdbcConnectionStringParserStrategy.getAdditionalConnectionStringProperties();
    }

    /*
     * 
     * @param username
     * @throws ValidationException
     */
    private void validateUsername(String username) throws ValidationException {
        if (username == null || username.equals("")) {
            throw new ValidationException(ValidationException.FIELD_USERNAME, ValidationException.REASON_CANNOT_BE_EMPTY);
        }
    }

    /*
     * 
     * @param password
     * @throws ValidationException
     */
    private void validatePassword(String password) throws ValidationException {
        if (password == null || password.equals("")) {
            throw new ValidationException(ValidationException.FIELD_PASSWORD, ValidationException.REASON_CANNOT_BE_EMPTY);
        }                
    }
}