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
package com.compuware.frameworks.security;

import java.util.Calendar;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import org.osgi.framework.ServiceException;

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityJdbcConfiguration;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityLdapConfiguration;
import com.compuware.frameworks.security.api.configuration.IConfiguration;

/**
 * 
 * @author tmyers
 * 
 */
public abstract class AbstractConfiguration implements IConfiguration {

    // The following is used to override default property values for the 
    // purposes of running unit tests.  There are two flavors of property
    // overrides:  DEV-WKS (a.k.a. IDE) and DEV-INT (PDE-Hudson)
    public static final String DEV_WKS_TEST_ENVIRONMENT = "DEV-WKS";
    public static final String DEV_INT_TEST_ENVIRONMENT = "DEV-INT";
    public static final String TEST_ENVIRONMENT = System.getProperty("env");
    // The following can be either SQLServer or Oracle (depending upon time of day), but defaults to SQLServer
    public static String TEST_ENVIRONMENT_DATABASE_TYPE = ICompuwareSecurityJdbcConfiguration.SQLSERVER;
    
    /*
     * 
     */
    static {
        if (TEST_ENVIRONMENT != null) {
            // First, figure out which database type to use for the tests.  One could be explicitly specfied
            // via system property.  If so, use that.  Otherwise, determine based upon time of day.
            String testEnvironmentDatabaseType = System.getProperty("jdbc.test.dbtype");
            if (testEnvironmentDatabaseType != null && (testEnvironmentDatabaseType.equals(ICompuwareSecurityJdbcConfiguration.SQLSERVER) || testEnvironmentDatabaseType.toLowerCase().equals("sqlserver"))) {
                TEST_ENVIRONMENT_DATABASE_TYPE = ICompuwareSecurityJdbcConfiguration.SQLSERVER;
            } else if (testEnvironmentDatabaseType != null && (testEnvironmentDatabaseType.equals(ICompuwareSecurityJdbcConfiguration.ORACLE) || testEnvironmentDatabaseType.toLowerCase().equals("oracle"))) {
                TEST_ENVIRONMENT_DATABASE_TYPE = ICompuwareSecurityJdbcConfiguration.ORACLE;
            } else {
                // Even hours run SQL Server tests and odd hours run Oracle tests
                if (Calendar.getInstance().get(Calendar.HOUR_OF_DAY) % 2 == 0) {
                    TEST_ENVIRONMENT_DATABASE_TYPE = ICompuwareSecurityJdbcConfiguration.SQLSERVER;
                } else {
                    TEST_ENVIRONMENT_DATABASE_TYPE = ICompuwareSecurityJdbcConfiguration.ORACLE;
                }
            }
            System.setProperty("jdbc.test.dbtype", TEST_ENVIRONMENT_DATABASE_TYPE);
            setTestEnvironmentDatabaseTypeDefaultOverrides(TEST_ENVIRONMENT_DATABASE_TYPE);
        }
    }
    
    /**
     * 
     * @param testEnvironmentDatabaseType
     */
    public static final void setTestEnvironmentDatabaseTypeDefaultOverrides(String testEnvironmentDatabaseType) {
        
        if (TEST_ENVIRONMENT.toUpperCase().trim().equals(DEV_WKS_TEST_ENVIRONMENT)) {
            // DEV-WKS (local developer workstation using Eclipse IDE)
            System.setProperty(ICompuwareSecurityLdapConfiguration.LDAP_URL_KEY, "ldap://dtw-dev-css03:10389/ou=system");
            
            if (testEnvironmentDatabaseType.equalsIgnoreCase(ICompuwareSecurityJdbcConfiguration.ORACLE)) {
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, "jdbc:oracle:thin:@dtw012710portal:1521:cpwrSecurity");
                
                System.setProperty("jdbc.hostname", "dtw012710portal");
                System.setProperty("jdbc.port", "1521");
                System.setProperty("jdbc.dbname", "cpwrSecurity");
                System.setProperty("jdbc.additionalConnectionStringProperties", "");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, System.getProperty("user.name"));
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, "tiger");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SQL_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_SQL_DIALECT_VALUE);
                System.setProperty(ICompuwareSecurityJdbcConfiguration.HIBERNATE_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_HIBERNATE_DIALECT_VALUE);
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_DRIVER_CLASS_NAME_VALUE);
            } else {
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, "jdbc:jtds:sqlserver://localhost:1433/cpwrSecurity");
                System.setProperty("jdbc.hostname", "localhost");
                System.setProperty("jdbc.port", "1433");
                System.setProperty("jdbc.dbname", "cpwrSecurity");
                System.setProperty("jdbc.additionalConnectionStringProperties", "");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, "sa");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, "password");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SQL_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_SQL_DIALECT_VALUE);
                System.setProperty(ICompuwareSecurityJdbcConfiguration.HIBERNATE_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_HIBERNATE_DIALECT_VALUE);
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_DRIVER_CLASS_NAME_VALUE);
            }
        } else if (TEST_ENVIRONMENT.toUpperCase().trim().equals(DEV_INT_TEST_ENVIRONMENT)) {
            // DEV-INT (Hudson CI using PDE Build process)
            System.setProperty(ICompuwareSecurityLdapConfiguration.LDAP_URL_KEY, "ldap://dtw-dev-css03:10389/ou=system");
            
            if (testEnvironmentDatabaseType.equalsIgnoreCase(ICompuwareSecurityJdbcConfiguration.ORACLE)) {
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, "jdbc:oracle:thin:@dtw012710portal:1521:cpwrSecurity");
                System.setProperty("jdbc.hostname", "dtw012710portal");
                System.setProperty("jdbc.port", "1521");
                System.setProperty("jdbc.dbname", "cpwrSecurity");
                System.setProperty("jdbc.additionalConnectionStringProperties", "");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, "sa");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, "vantage");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SQL_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_SQL_DIALECT_VALUE);
                System.setProperty(ICompuwareSecurityJdbcConfiguration.HIBERNATE_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_HIBERNATE_DIALECT_VALUE);
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_DRIVER_CLASS_NAME_VALUE);
            } else {
            	String ostype = System.getProperty("os.name");
            	if (ostype.startsWith("Windows")) {
            		// Hudson build under windows
	                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, "jdbc:jtds:sqlserver://localhost:1433/cpwrSecurity");
	                System.setProperty("jdbc.hostname", "localhost");
            	} else {
            		// PDE nightly build under linux
                    System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, "jdbc:jtds:sqlserver://dtw-dev-css03:1433/cpwrSecurity");
                    System.setProperty("jdbc.hostname", "dtw-dev-css03");
            	}
                System.setProperty("jdbc.port", "1433");
                System.setProperty("jdbc.dbname", "cpwrSecurity");
                System.setProperty("jdbc.additionalConnectionStringProperties", "");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, "sa");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, "vantage");
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_SQL_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_SQL_DIALECT_VALUE);
                System.setProperty(ICompuwareSecurityJdbcConfiguration.HIBERNATE_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_HIBERNATE_DIALECT_VALUE);
                System.setProperty(ICompuwareSecurityJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_DRIVER_CLASS_NAME_VALUE);
            }
        } else {
            throw new RuntimeException("Unsupported test environment: [" 
                + TEST_ENVIRONMENT
                + "].  Valid values are: [" 
                + DEV_WKS_TEST_ENVIRONMENT
                + "] and ["
                + DEV_INT_TEST_ENVIRONMENT
                + "].  Please specify a valid test environment value for a system property define and try again.");
        }
        
    }
    
    /** */
    public final static Map<String, String> DEFAULT_JDBC_C3P0_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_ACQUIRE_INCREMENT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_ACQUIRE_INCREMENT_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_MIN_POOL_SIZE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_MIN_POOL_SIZE_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_INITIAL_POOL_SIZE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_INITIAL_POOL_SIZE_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_MAX_POOL_SIZE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_MAX_POOL_SIZE_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_MAX_CONNECTION_AGE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_MAX_CONNECTION_AGE_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_MAX_IDLE_TIME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_MAX_IDLE_TIME_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_MAX_IDLE_TIME_EXCESS_CONNECTIONS_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_MAX_IDLE_TIME_EXCESS_CONNECTIONS_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_IDLE_CONNECTION_TEST_PERIOD_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_IDLE_CONNECTION_TEST_PERIOD_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_TEST_CONNECTION_ON_CHECKIN_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_TEST_CONNECTION_ON_CHECKIN_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_TEST_CONNECTION_ON_CHECKOUT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_TEST_CONNECTION_ON_CHECKOUT_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_MAX_STATEMENTS_PER_CONNECTION_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_MAX_STATEMENTS_PER_CONNECTION_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_ACQUIRE_RETRY_ATTEMPTS_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_ACQUIRE_RETRY_ATTEMPTS_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_ACQUIRE_RETRY_DELAY_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_ACQUIRE_RETRY_DELAY_VALUE);
        DEFAULT_JDBC_C3P0_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_C3P0_BREAK_AFTER_ACQUIRE_FAILURE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_C3P0_BREAK_AFTER_ACQUIRE_FAILURE_VALUE);
    }

    /** */
    public final static Map<String, String> DEFAULT_HIBERNATE_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_GENERATE_STATISTICS_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_GENERATE_STATISTICS_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_SHOW_SQL_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_SHOW_SQL_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_FORMAT_SQL_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_FORMAT_SQL_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_USE_SQL_COMMENTS_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_USE_SQL_COMMENTS_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_CACHE_USE_QUERY_CACHE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_CACHE_USE_QUERY_CACHE_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_CACHE_USE_SECOND_LEVEL_CACHE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_CACHE_USE_SECOND_LEVEL_CACHE_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_MAX_FETCH_DEPTH_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_MAX_FETCH_DEPTH_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_DEFAULT_BATCH_FETCH_SIZE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_DEFAULT_BATCH_FETCH_SIZE_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_JDBC_FETCH_SIZE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_JDBC_FETCH_SIZE_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_JDBC_BATCH_SIZE_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_JDBC_BATCH_SIZE_VALUE);
        DEFAULT_HIBERNATE_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_JDBC_BATCH_VERSIONED_DATA_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_HIBERNATE_JDBC_BATCH_VERSIONED_DATA_VALUE);
    }    
    
    /** */
    public final static Map<String, String> DEFAULT_DERBY_JDBC_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_DERBY_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_CONFIGURATION_VERSION_VALUE);
        DEFAULT_DERBY_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_DERBY_DRIVER_CLASS_NAME_VALUE);
        DEFAULT_DERBY_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_DERBY_CONNECTION_STRING_VALUE);
        DEFAULT_DERBY_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_DERBY_SERVICE_ACCOUNT_USERNAME_VALUE);
        DEFAULT_DERBY_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_DERBY_SERVICE_ACCOUNT_PASSWORD_VALUE);
        DEFAULT_DERBY_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_TIMEOUT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_TIMEOUT_VALUE);
        DEFAULT_DERBY_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SQL_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_DERBY_SQL_DIALECT_VALUE);
        DEFAULT_DERBY_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_DERBY_HIBERNATE_DIALECT_VALUE);
        DEFAULT_DERBY_JDBC_PROPERTIES.putAll(DEFAULT_JDBC_C3P0_PROPERTIES);
        DEFAULT_DERBY_JDBC_PROPERTIES.putAll(DEFAULT_HIBERNATE_PROPERTIES);
    }
    
    /** */
    public final static Map<String, String> DEFAULT_SQLSERVER_JDBC_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_CONFIGURATION_VERSION_VALUE);
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_DRIVER_CLASS_NAME_VALUE);
        
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, 
                getPropertyValue(
                        ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, 
                        ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_CONNECTION_STRING_VALUE));
        
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, 
                getPropertyValue(                         
                        ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY,
                        ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_SERVICE_ACCOUNT_USERNAME_VALUE));
        
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, 
                getPropertyValue(                         
                        ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY,
                        ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_SERVICE_ACCOUNT_PASSWORD_VALUE));
        
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_TIMEOUT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_TIMEOUT_VALUE);
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SQL_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_SQL_DIALECT_VALUE);
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_HIBERNATE_DIALECT_VALUE);
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.putAll(DEFAULT_JDBC_C3P0_PROPERTIES);
        DEFAULT_SQLSERVER_JDBC_PROPERTIES.putAll(DEFAULT_HIBERNATE_PROPERTIES);
    }

    /** */
    public final static Map<String, String> DEFAULT_ORACLE_JDBC_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_ORACLE_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_CONFIGURATION_VERSION_VALUE);
        DEFAULT_ORACLE_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_DRIVER_CLASS_NAME_VALUE);
        
        DEFAULT_ORACLE_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, 
                getPropertyValue(
                        ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, 
                        ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_CONNECTION_STRING_VALUE));
        
        DEFAULT_ORACLE_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, 
                getPropertyValue(                         
                        ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY,
                        ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_SERVICE_ACCOUNT_USERNAME_VALUE));
        
        DEFAULT_ORACLE_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, 
                getPropertyValue(                         
                        ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY,
                        ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_SERVICE_ACCOUNT_PASSWORD_VALUE));
        
        DEFAULT_ORACLE_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_TIMEOUT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_TIMEOUT_VALUE);
        DEFAULT_ORACLE_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.JDBC_SQL_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_SQL_DIALECT_VALUE);
        DEFAULT_ORACLE_JDBC_PROPERTIES.put(ICompuwareSecurityJdbcConfiguration.HIBERNATE_DIALECT_KEY, ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_ORACLE_HIBERNATE_DIALECT_VALUE);
        DEFAULT_ORACLE_JDBC_PROPERTIES.putAll(DEFAULT_JDBC_C3P0_PROPERTIES);
        DEFAULT_ORACLE_JDBC_PROPERTIES.putAll(DEFAULT_HIBERNATE_PROPERTIES);
    }
    
    /** */
    public final static Map<String, String> DEFAULT_JDBC_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_JDBC_PROPERTIES.putAll(DEFAULT_SQLSERVER_JDBC_PROPERTIES);
    }
    
    /** */
    public final static Map<String, String> DEFAULT_APACHEDS_LDAP_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_CONFIGURATION_VERSION_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_IS_LDAP_AUTHENTICATION_ENABLED_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_TYPE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_TYPE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_URL_KEY, getPropertyValue(ICompuwareSecurityLdapConfiguration.LDAP_URL_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_URL_VALUE));
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_SERVICE_ACCOUNT_USERNAME_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_SERVICE_ACCOUNT_PASSWORD_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_REFERRAL_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_REFERRAL_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_REFERRAL_LIMIT_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_REFERRAL_LIMIT_VALUE);        
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_TIMEOUT_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_TIMEOUT_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USE_TLS_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_USE_TLS_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_PAGE_SIZE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_PAGE_SIZE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_USER_USERNAME_ATTRIBUTE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_USER_EMAIL_ADDRESS_ATTRIBUTE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_USER_FIRST_NAME_ATTRIBUTE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_USER_LAST_NAME_ATTRIBUTE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_SEARCH_BASE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_USER_SEARCH_BASE_VALUE);        
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_USER_SEARCH_FILTER_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_USER_GROUPS_SEARCH_BASE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_USER_GROUPS_SEARCH_FILTER_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_GROUP_GROUPNAME_ATTRIBUTE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_GROUP_DESCRIPTION_ATTRIBUTE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_GROUP_LIST_SEARCH_BASE_VALUE);
        DEFAULT_APACHEDS_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_APACHEDS_GROUP_LIST_SEARCH_FILTER_VALUE);
    }
    
    /** */
    public final static Map<String, String> DEFAULT_ACTIVEDIR_LDAP_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_CONFIGURATION_VERSION_VALUE);        
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_IS_LDAP_AUTHENTICATION_ENABLED_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_TYPE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_LDAP_TYPE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_URL_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_URL_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_SERVICE_ACCOUNT_USERNAME_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_SERVICE_ACCOUNT_PASSWORD_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_REFERRAL_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_REFERRAL_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_REFERRAL_LIMIT_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_REFERRAL_LIMIT_VALUE);        
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_TIMEOUT_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_TIMEOUT_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USE_TLS_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_USE_TLS_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_PAGE_SIZE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_PAGE_SIZE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_USER_USERNAME_ATTRIBUTE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_USER_EMAIL_ADDRESS_ATTRIBUTE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_USER_FIRST_NAME_ATTRIBUTE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_USER_LAST_NAME_ATTRIBUTE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_SEARCH_BASE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_USER_SEARCH_BASE_VALUE);        
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_USER_SEARCH_FILTER_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_USER_GROUPS_SEARCH_BASE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_USER_GROUPS_SEARCH_FILTER_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_GROUP_GROUPNAME_ATTRIBUTE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_GROUP_DESCRIPTION_ATTRIBUTE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_GROUP_LIST_SEARCH_BASE_VALUE);
        DEFAULT_ACTIVEDIR_LDAP_PROPERTIES.put(ICompuwareSecurityLdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY, ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_ACTIVEDIR_GROUP_LIST_SEARCH_FILTER_VALUE);
    }
    
    /** */
    public final static Map<String, String> DEFAULT_LDAP_PROPERTIES = new TreeMap<String, String>();
    static {
        DEFAULT_LDAP_PROPERTIES.putAll(DEFAULT_APACHEDS_LDAP_PROPERTIES);
    }
    
    
    /* */
    private Map<String, String> configurationValues;
    
    /**
     * @param configurationValues
     */
    public AbstractConfiguration(Map<String, String> configurationValues) {
        
        if (configurationValues == null) {
            throw new ServiceException("configurationValues cannot be null");
        }
        
        this.configurationValues = configurationValues;
        setSystemPropertyOverrides(this.configurationValues);
    }
        
    /**
     * 
     * @return
     */
    public final Map<String, String> getAllConfigurationValues() {
        
        Map<String, String> map = new TreeMap<String, String>();
        map.putAll(this.configurationValues);
        return map;
    }

    /**
     * 
     * @param key
     * @return
     */
    public final String getConfigurationValue(String key) {
        
        String value = this.configurationValues.get(key);            
        if (value == null) {
            
            String lowerCaseKey = key.toLowerCase();
            
            // Since the keys are stored in the map in a case-sensitive manner, try performing a case-insensitive linear search for the given key.
            Iterator<String> iterator = this.configurationValues.keySet().iterator();
            while (iterator.hasNext()) {
                
                String iteratatedKey = iterator.next();
                String iteratedLowerCaseKey = iteratatedKey.toLowerCase();
                if (iteratedLowerCaseKey.equals(lowerCaseKey)) {
                    
                    value = this.configurationValues.get(iteratatedKey);
                    break;
                }
            }
        }
                
        return value;
    }

    /**
     * 
     * @param key
     * @param value
     */
    public void setConfigurationValue(String key, String value) {

        this.configurationValues.put(key, value);
    }

    /**
     * 
     * @param allConfigurationValues
     */
    public final void setAllConfigurationValues(Map<String, String> allConfigurationValues) {
        
        this.configurationValues.putAll(allConfigurationValues);
    }

    /**
     * 
     * @param configurationValues
     */
    public static final void setSystemPropertyOverrides(Map<String, String> configurationValues) {
        
        String disableSystemPropertyOverride = System.getProperty("disableSystemPropertyOverride");
        if (disableSystemPropertyOverride == null || disableSystemPropertyOverride.toLowerCase().trim().equals("false")) {
            Iterator<String> iterator = configurationValues.keySet().iterator();
            while (iterator.hasNext()) {
                
                String key = iterator.next();
                String systemPropertyValue = System.getProperty(key);
                
                if (systemPropertyValue != null) {
                    configurationValues.put(key, systemPropertyValue);
                }
            }
        }
    }

    /**
     * Returns the value for the given key in one of two ways:<br>
     * <ol>
     *   <li>An overridden value specified by the existence of a system property.
     *   <li>Otherwise, the value specified by <code>defaultValue</code> is returned.</li>
     * </ol>
     * @param key
     * @param defaultValue
     * @return
     */
    public static final String getPropertyValue(String key, String defaultValue) {
        
        String value = System.getProperty(key);
        if (value != null) {
            return value;
        }
        return defaultValue;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {
        
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        Iterator<String> iterator = this.configurationValues.keySet().iterator();
        while (iterator.hasNext()) {
            String key = iterator.next();
            String displayValue = null;
            if (key.toLowerCase().indexOf("password") >= 0) {
                displayValue = "PROTECTED_VALUE";    
            } else {
                displayValue = this.configurationValues.get(key);
            }
            sb.append(key);
            sb.append("=");
            sb.append(displayValue);
            if (iterator.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append("]");
        return sb.toString();
    }    
}