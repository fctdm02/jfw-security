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

import com.compuware.frameworks.security.service.api.configuration.IConfigurationService;
import com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration;
import com.compuware.frameworks.security.service.api.exception.ServiceException;


/**
 * 
 * @author tmyers
 */
public class SqlServerJdbcConnectionStringParserStrategy extends AbstractJdbcConnectionStringParserStrategy {

    /**
     * 
     * @param jdbcConnectionString
     */
    public SqlServerJdbcConnectionStringParserStrategy( 
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
        // jdbc:jtds:sqlserver://localhost:1433/cpwrSecurity
        if (this.jdbcConnectionString == null || this.jdbcConnectionString.isEmpty() || !this.jdbcConnectionString.startsWith(IJdbcConfiguration.SQLSERVER_CONNECTION_STRING_PREFIX)) {
            throw new ServiceException("Invalid SQL Server JDBC Connection string: " + this.jdbcConnectionString);
        }
        
        int firstColonIndex = this.jdbcConnectionString.indexOf(IJdbcConfiguration.COLON_CHAR, IJdbcConfiguration.SQLSERVER_CONNECTION_STRING_PREFIX.length() + 1);
        if (firstColonIndex != -1) {

            int beginIndex = IJdbcConfiguration.SQLSERVER_CONNECTION_STRING_PREFIX.length();
            this.hostname = this.jdbcConnectionString.substring(beginIndex, firstColonIndex);
            
            int forwardSlashIndex = this.jdbcConnectionString.indexOf(IJdbcConfiguration.FORWARD_SLASH_CHAR, firstColonIndex + 1);
            this.port = this.jdbcConnectionString.substring(firstColonIndex + 1, forwardSlashIndex);
            
            int semiColonIndex = this.jdbcConnectionString.indexOf(IJdbcConfiguration.SEMI_COLON_CHAR, forwardSlashIndex + 1);
            if (semiColonIndex != -1) {
                
                this.databaseName = this.jdbcConnectionString.substring(forwardSlashIndex + 1, semiColonIndex);
                
                this.additionalConnectionStringProperties = this.jdbcConnectionString.substring(semiColonIndex + 1);
                
                String windowsIntegratedSecurity = IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE_PROPERTY_KEY + IJdbcConfiguration.EQUALS_CHAR + IJdbcConfiguration.TRUE;
                String windowsDomainAuthentication = IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE_PROPERTY_KEY + IJdbcConfiguration.EQUALS_CHAR;
                if (this.additionalConnectionStringProperties.contains(windowsIntegratedSecurity)) {

                    String osName = System.getProperty(IConfigurationService.OS_NAME_SYSTEM_PROPERTY);
                    if (osName.startsWith(IConfigurationService.OS_NAME_WINDOWS)) {

                        this.dbAuthType = IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE;
                        this.additionalConnectionStringProperties = this.additionalConnectionStringProperties.replace(windowsIntegratedSecurity, "");
                        this.additionalConnectionStringProperties = this.additionalConnectionStringProperties.replace(";;", ";");
                    } else {
                        throw new ServiceException("Cannot use Windows Integrated Security for DataSource authentication on the Security Server with operating system: " + osName);
                    }
                                        
                } else if (this.additionalConnectionStringProperties.contains(windowsDomainAuthentication)) {
                    
                    this.dbAuthType = IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE;
                    int domainIndex = this.additionalConnectionStringProperties.indexOf(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE_PROPERTY_KEY);
                    int additionalPropertiesSemiColonIndex = this.additionalConnectionStringProperties.indexOf(IJdbcConfiguration.SEMI_COLON_CHAR, domainIndex + 1);
                    if (additionalPropertiesSemiColonIndex != -1) {
                        this.windowsDomain = this.additionalConnectionStringProperties.substring(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE_PROPERTY_KEY.length() + 1, additionalPropertiesSemiColonIndex);    
                    } else {
                        this.windowsDomain = this.additionalConnectionStringProperties.substring(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE_PROPERTY_KEY.length() + 1);
                    }
                    this.additionalConnectionStringProperties = this.additionalConnectionStringProperties.replace(windowsDomainAuthentication + this.windowsDomain, "");
                    this.additionalConnectionStringProperties = this.additionalConnectionStringProperties.replace(";;", ";");
                    
                } else {
                    this.dbAuthType = IJdbcConfiguration.LOCAL_DB_AUTH_TYPE;
                }
                
            } else {
                this.databaseName = this.jdbcConnectionString.substring(forwardSlashIndex + 1);            
            }
        }
    }
    
    /**
     * @return
     */
    public String getDatabaseType() {
        return IJdbcConfiguration.SQLSERVER;        
    }    
}