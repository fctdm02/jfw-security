/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2010 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.api.configuration;


/**
  <a href="http://msdn.microsoft.com/en-us/library/ms378988.aspx">MS SQLServer JDBC Driver Connection Properties</a>
  <a href="http://msdn.microsoft.com/en-us/library/ms378672.aspx">MS SQLServer JDBC Driver Configuration Properties</a>
  <a href="http://www.mchange.com/projects/c3p0/index.html#configuration_properties">C3P0 Configuration Properties</a>
  <a href="http://ehcache.org/documentation/hibernate.html">EhCache Configuration Properties</a>
  <a href="http://docs.jboss.org/hibernate/core/3.3/reference/en/html/session-configuration.html">Hibernate Configuration</a>
  
 <pre>    
 # Used for optimistic locking
 jdbc.configurationVersion=1
 
 # C3P0 Connection Pooled JDBC DataSource:
 # =======================================
 # Basic Pool Configuration:
 acquireIncrement=3
 minPoolSize=3
 initialPoolSize=3
 maxPoolSize=15
 
 # Managing Pool Size and Connection Age:
 maxConnectionAge=0
 maxIdleTime=0
 maxIdleTimeExcessConnections=0
 
 # Configuring Connection Testing:
 idleConnectionTestPeriod=300
 testConnectionOnCheckin=false
 testConnectionOnCheckout=false
  
 # Configuring Statement Pooling:
 maxStatementsPerConnection=20
  
 # Configuring Recovery From Database Outages:
 acquireRetryAttempts=3
 acquireRetryDelay=1000
 breakAfterAcquireFailure=false
 
  
 # EhCache 
 # ========
 # Domain Objects:
 domainObjectClass=className
 maxElementsInMemory=10000
 eternal=false
 timeToIdleSeconds=300
 timeToLiveSeconds=600
 overflowToDisk=true
  
 # Domain Object Collections:
 domainObjectClass.collection=className.collectionName
 
 
 # Hibernate
 # =========
 hibernate.dialect=com.compuware.frameworks.security.persistence.hibernate.dialect.CompuwareSqlServerHibernateDialect
 hibernate.cache.use_second_level_cache=true
 hibernate.cache.use_query_cache=true
 hibernate.show_sql=false
 hibernate.format_sql=false
 hibernate.max_fetch_depth=3
 hibernate.jdbc.batch_size=5
 hibernate.jdbc.fetch_size=25
 hibernate.default_batch_fetch_size=8
 hibernate.generate_statistics=false
 hibernate.use_sql_comments=false
 hibernate.jdbc.batch_versioned_data=true 
 </pre>
 * 
 * @author tmyers
 * 
 * TODO: TDM:   
 * JMX:
 *http://www.mchange.com/projects/c3p0/index.html#jmx_configuration_and_management 
 *http://ehcache.org/documentation/samples.html#Cache_Statistics_and_Monitoring 
 *
 */
public interface ICompuwareSecurityJdbcConfiguration  {

    /** */
    String DERBY = "Embedded Derby";
    /** */
    String SQLSERVER = "SQL Server";
    /** */
    String ORACLE = "Oracle";

    
    /** */
    char COLON_CHAR = ':';
    /** */
    char SEMI_COLON_CHAR = ';';
    /** */
    char FORWARD_SLASH_CHAR = '/';
    /** */
    char EQUALS_CHAR = '=';
    /** */
    String TRUE = "true";
    /** */
    String FALSE = "false";
    
    
    /** */
    String DATABASE_TYPE_EXCEPTION_MESSAGE_PREFIX = "Unsupported database type: [";
        
    /** */
    String DATABASE_TYPE_EXCEPTION_MESSAGE_SUFFIX = "].  Supported types are: ["
        + DERBY
        + ", "
        + SQLSERVER
        + " and "
        + ORACLE
        + "].";
    
        
    /** */
    String JDBC_CONFIGURATION_VERSION_KEY = "jdbc.configurationVersion";
    /** */
    String JDBC_DRIVER_CLASS_NAME_KEY = "jdbc.driverClassName";
    /** */
    String JDBC_CONNECTION_STRING_KEY = "jdbc.connectionString";
    /** */
    String JDBC_SERVICE_ACCOUNT_USERNAME_KEY = "jdbc.username";
    /** */    
    String JDBC_SERVICE_ACCOUNT_PASSWORD_KEY = "jdbc.password";
    /** */
    String JDBC_SERVICE_ACCOUNT_PASSWORD_CLEAR_TEXT_FLAG_KEY = "jdbc.passwordcleartext";
    
    /** */
    String JDBC_TIMEOUT_KEY = "jdbc.timeout";
    /** */
    String JDBC_SQL_DIALECT_KEY = "jdbc.sqlDialect";    

    
    /** */
    String DEFAULT_JDBC_CONFIGURATION_VERSION_VALUE = "1";    
    
    /** 
     * The username/password represent credentials stored in the local SQLServer DB 
     * (For non-windows, this is the only option). 
     */
    String LOCAL_DB_AUTH_TYPE = "LOCAL_DB_AUTH_TYPE";

    /** 
     * The username/password represent credentials stored in the 'windowsDomain' 
     * Windows domain. 
     */
    String WINDOWS_DOMAIN_DB_AUTH_TYPE = "WINDOWS_DOMAIN_DB_AUTH_TYPE";
    String WINDOWS_DOMAIN_DB_AUTH_TYPE_PROPERTY_KEY = "domain";
    
    /**
     * The username/password combination are ignored, as the currently logged in user
     * is used.
     */
    String WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE = "WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE";
    String WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE_PROPERTY_KEY = "integratedSecurity";
    
    
    String JDBC_C3P0_ACQUIRE_INCREMENT_KEY = "jdbc.c3p0.acquireIncrement";
    String JDBC_C3P0_MIN_POOL_SIZE_KEY = "jdbc.c3p0.minPoolSize";
    String JDBC_C3P0_INITIAL_POOL_SIZE_KEY = "jdbc.c3p0.initialPoolSize";
    String JDBC_C3P0_MAX_POOL_SIZE_KEY = "jdbc.c3p0.maxPoolSize";
    String JDBC_C3P0_MAX_CONNECTION_AGE_KEY = "jdbc.c3p0.maxConnectionAge";
    String JDBC_C3P0_MAX_IDLE_TIME_KEY = "jdbc.c3p0.maxIdleTime";
    String JDBC_C3P0_MAX_IDLE_TIME_EXCESS_CONNECTIONS_KEY = "jdbc.c3p0.maxIdleTimeExcessConnections";
    String JDBC_C3P0_IDLE_CONNECTION_TEST_PERIOD_KEY = "jdbc.c3p0.idleConnectionTestPeriod";
    String JDBC_C3P0_TEST_CONNECTION_ON_CHECKIN_KEY = "jdbc.c3p0.testConnectionOnCheckin";
    String JDBC_C3P0_TEST_CONNECTION_ON_CHECKOUT_KEY = "jdbc.c3p0.testConnectionOnCheckout";
    String JDBC_C3P0_MAX_STATEMENTS_PER_CONNECTION_KEY = "jdbc.c3p0.maxStatementsPerConnection";
    String JDBC_C3P0_ACQUIRE_RETRY_ATTEMPTS_KEY = "jdbc.c3p0.acquireRetryAttempts";
    String JDBC_C3P0_ACQUIRE_RETRY_DELAY_KEY = "jdbc.c3p0.acquireRetryDelay";
    String JDBC_C3P0_BREAK_AFTER_ACQUIRE_FAILURE_KEY = "jdbc.c3p0.breakAfterAcquireFailure";
    
    String HIBERNATE_DIALECT_KEY = "hibernate.dialect";
    String HIBERNATE_GENERATE_STATISTICS_KEY = "hibernate.generate_statistics";
    String HIBERNATE_SHOW_SQL_KEY = "hibernate.show_sql";
    String HIBERNATE_FORMAT_SQL_KEY = "hibernate.format_sql";
    String HIBERNATE_USE_SQL_COMMENTS_KEY = "hibernate.use_sql_comments";
    String HIBERNATE_CACHE_USE_QUERY_CACHE_KEY = "hibernate.cache.use_query_cache";
    String HIBERNATE_CACHE_USE_SECOND_LEVEL_CACHE_KEY = "hibernate.cache.use_second_level_cache";
    String HIBERNATE_MAX_FETCH_DEPTH_KEY = "hibernate.max_fetch_depth";
    String HIBERNATE_DEFAULT_BATCH_FETCH_SIZE_KEY = "hibernate.default_batch_fetch_size";
    String HIBERNATE_JDBC_FETCH_SIZE_KEY = "hibernate.jdbc.fetch_size";
    String HIBERNATE_JDBC_BATCH_SIZE_KEY = "hibernate.jdbc.batch_size";
    String HIBERNATE_JDBC_BATCH_VERSIONED_DATA_KEY = "hibernate.jdbc.batch_versioned_data";
    

    
    String DEFAULT_JDBC_C3P0_ACQUIRE_INCREMENT_VALUE = "5";
    String DEFAULT_JDBC_C3P0_MIN_POOL_SIZE_VALUE = "10";
    String DEFAULT_JDBC_C3P0_INITIAL_POOL_SIZE_VALUE = "10";
    String DEFAULT_JDBC_C3P0_MAX_POOL_SIZE_VALUE = "20";
    String DEFAULT_JDBC_C3P0_MAX_CONNECTION_AGE_VALUE = "0";
    String DEFAULT_JDBC_C3P0_MAX_IDLE_TIME_VALUE = "0";
    String DEFAULT_JDBC_C3P0_MAX_IDLE_TIME_EXCESS_CONNECTIONS_VALUE = "0";
    String DEFAULT_JDBC_C3P0_IDLE_CONNECTION_TEST_PERIOD_VALUE = "300";
    String DEFAULT_JDBC_C3P0_TEST_CONNECTION_ON_CHECKIN_VALUE = "false";
    String DEFAULT_JDBC_C3P0_TEST_CONNECTION_ON_CHECKOUT_VALUE = "false";
    String DEFAULT_JDBC_C3P0_MAX_STATEMENTS_PER_CONNECTION_VALUE = "50";
    String DEFAULT_JDBC_C3P0_ACQUIRE_RETRY_ATTEMPTS_VALUE = "3";
    String DEFAULT_JDBC_C3P0_ACQUIRE_RETRY_DELAY_VALUE = "1000";
    String DEFAULT_JDBC_C3P0_BREAK_AFTER_ACQUIRE_FAILURE_VALUE = "false";
    
    String DEFAULT_HIBERNATE_GENERATE_STATISTICS_VALUE = "false";
    String DEFAULT_HIBERNATE_SHOW_SQL_VALUE = "false";
    String DEFAULT_HIBERNATE_FORMAT_SQL_VALUE = "false";
    String DEFAULT_HIBERNATE_USE_SQL_COMMENTS_VALUE = "false";
    String DEFAULT_HIBERNATE_CACHE_USE_QUERY_CACHE_VALUE = "true";
    String DEFAULT_HIBERNATE_CACHE_USE_SECOND_LEVEL_CACHE_VALUE = "true";
    String DEFAULT_HIBERNATE_MAX_FETCH_DEPTH_VALUE = "3";
    String DEFAULT_HIBERNATE_DEFAULT_BATCH_FETCH_SIZE_VALUE = "8";
    String DEFAULT_HIBERNATE_JDBC_FETCH_SIZE_VALUE = "25";
    String DEFAULT_HIBERNATE_JDBC_BATCH_SIZE_VALUE = "5";
    String DEFAULT_HIBERNATE_JDBC_BATCH_VERSIONED_DATA_VALUE = "true";
    
    
    /** */
    String DEFAULT_JDBC_TIMEOUT_VALUE = "15"; //TODO: TDM: This is actually for the SQLServer "loginTimeout" connection property.        
    /** */
    String DEFAULT_JDBC_DERBY_DRIVER_CLASS_NAME_VALUE              = "org.apache.derby.jdbc.EmbeddedDriver";
    /** */
    String DERBY_CONNECTION_STRING_JDBC_PROTOCOL                    = "derby";    
    /** */
    String DERBY_CONNECTION_STRING_PREFIX                          = "jdbc:" + DERBY_CONNECTION_STRING_JDBC_PROTOCOL + ":";
    /** */
    String DEFAULT_JDBC_DERBY_CONNECTION_HOSTNAME_VALUE            = "";
    /** */
    String DEFAULT_JDBC_DERBY_CONNECTION_PORT_VALUE                = "";
    /** */
    String DEFAULT_JDBC_DERBY_CONNECTION_DB_NAME_VALUE             = "cpwrSecurityDB";
    /** */
    String DEFAULT_JDBC_DERBY_CONNECTION_DB_AUTH_TYPE_VALUE        = LOCAL_DB_AUTH_TYPE;
    /** */
    String DEFAULT_JDBC_DERBY_CONNECTION_WINDOWS_DOMAIN_NAME_VALUE = "";
    /** */
    String DEFAULT_JDBC_DERBY_CONNECTION_ADDITIONAL_PROPERTIES     = "create=true";        
    /** */
    String DEFAULT_JDBC_DERBY_CONNECTION_STRING_VALUE              = DERBY_CONNECTION_STRING_PREFIX 
                                                                     + DEFAULT_JDBC_DERBY_CONNECTION_DB_NAME_VALUE 
                                                                     + SEMI_COLON_CHAR 
                                                                     + DEFAULT_JDBC_DERBY_CONNECTION_ADDITIONAL_PROPERTIES;
    /** */
    String DEFAULT_JDBC_DERBY_SERVICE_ACCOUNT_USERNAME_VALUE       = "cpwrSecurity";
    /** */
    String DEFAULT_JDBC_DERBY_SERVICE_ACCOUNT_PASSWORD_VALUE       = "cpwrSecurity";
    /** */
    String DEFAULT_JDBC_DERBY_SQL_DIALECT_VALUE                    = "com.compuware.frameworks.security.persistence.dao.jdbc.DerbyAclSql";
    /** */
    String DEFAULT_JDBC_DERBY_HIBERNATE_DIALECT_VALUE              = "org.hibernate.dialect.DerbyDialect";
    
    
    
    /** */
    String DEFAULT_JDBC_SQLSERVER_DRIVER_CLASS_NAME_VALUE         = "net.sourceforge.jtds.jdbc.Driver";
    /** */
    String SQLSERVER_CONNECTION_STRING_JDBC_PROTOCOL              = "jtds";        
    /** */
    String SQLSERVER_CONNECTION_STRING_PREFIX                     = "jdbc:" + SQLSERVER_CONNECTION_STRING_JDBC_PROTOCOL + ":sqlserver://";    
    /** */
    String DEFAULT_JDBC_SQLSERVER_CONNECTION_HOSTNAME_VALUE       = "localhost";
    /** */
    String DEFAULT_JDBC_SQLSERVER_CONNECTION_PORT_VALUE           = "1433";
    /** */
    String DEFAULT_JDBC_SQLSERVER_CONNECTION_DB_NAME_VALUE        = "cpwrSecurity";
    /** */
    String DEFAULT_JDBC_SQLSERVER_CONNECTION_DB_AUTH_TYPE_VALUE   = LOCAL_DB_AUTH_TYPE;
    /** */
    String DEFAULT_JDBC_SQLSERVER_CONNECTION_WINDOWS_DOMAIN_NAME_VALUE = "";
    /** */
    String DEFAULT_JDBC_SQLSERVER_CONNECTION_ADDITIONAL_PROPERTIES     = "";    
    /** */
    String DEFAULT_JDBC_SQLSERVER_CONNECTION_STRING_VALUE         = SQLSERVER_CONNECTION_STRING_PREFIX
                                                                    + DEFAULT_JDBC_SQLSERVER_CONNECTION_HOSTNAME_VALUE
                                                                    + COLON_CHAR
                                                                    + DEFAULT_JDBC_SQLSERVER_CONNECTION_PORT_VALUE
                                                                    + FORWARD_SLASH_CHAR
                                                                    + DEFAULT_JDBC_SQLSERVER_CONNECTION_DB_NAME_VALUE;
    /** */
    String DEFAULT_JDBC_SQLSERVER_SERVICE_ACCOUNT_USERNAME_VALUE  = "sa";
    /** */
    String DEFAULT_JDBC_SQLSERVER_SERVICE_ACCOUNT_PASSWORD_VALUE  = "password";
    /** */
    String DEFAULT_JDBC_SQLSERVER_SQL_DIALECT_VALUE               = "com.compuware.frameworks.security.persistence.dao.jdbc.SqlServerAclSql";
    /** */
    String DEFAULT_JDBC_SQLSERVER_HIBERNATE_DIALECT_VALUE         = "com.compuware.frameworks.security.persistence.hibernate.dialect.CompuwareSqlServerHibernateDialect";
    
    
    
    
    /** */
    String DEFAULT_JDBC_ORACLE_DRIVER_CLASS_NAME_VALUE         = "oracle.jdbc.OracleDriver";
    /** */
    String ORACLE_CONNECTION_STRING_JDBC_PROTOCOL           = "oracle";        
    /** */
    String ORACLE_CONNECTION_STRING_PREFIX                     = "jdbc:" + ORACLE_CONNECTION_STRING_JDBC_PROTOCOL + ":thin:@";    
    /** */
    String DEFAULT_JDBC_ORACLE_CONNECTION_HOSTNAME_VALUE       = "dtw012710portal";
    /** */
    String DEFAULT_JDBC_ORACLE_CONNECTION_PORT_VALUE           = "1521";
    /** */
    String DEFAULT_JDBC_ORACLE_CONNECTION_DB_NAME_VALUE        = "cpwrSecurity";
    /** */
    String DEFAULT_JDBC_ORACLE_CONNECTION_DB_AUTH_TYPE_VALUE   = LOCAL_DB_AUTH_TYPE;
    /** */
    String DEFAULT_JDBC_ORACLE_CONNECTION_WINDOWS_DOMAIN_NAME_VALUE = "";
    /** */
    String DEFAULT_JDBC_ORACLE_CONNECTION_ADDITIONAL_PROPERTIES     = "";    
    /** */
    String DEFAULT_JDBC_ORACLE_CONNECTION_STRING_VALUE         = ORACLE_CONNECTION_STRING_PREFIX
                                                                 + DEFAULT_JDBC_ORACLE_CONNECTION_HOSTNAME_VALUE
                                                                 + COLON_CHAR
                                                                 + DEFAULT_JDBC_ORACLE_CONNECTION_PORT_VALUE
                                                                 + COLON_CHAR
                                                                 + DEFAULT_JDBC_ORACLE_CONNECTION_DB_NAME_VALUE; 
    /** */
    String DEFAULT_JDBC_ORACLE_SERVICE_ACCOUNT_USERNAME_VALUE  = System.getProperty("user.name");
    /** */
    String DEFAULT_JDBC_ORACLE_SERVICE_ACCOUNT_PASSWORD_VALUE  = "tiger";
    /** */
    String DEFAULT_JDBC_ORACLE_SQL_DIALECT_VALUE               = "com.compuware.frameworks.security.persistence.dao.jdbc.OracleAclSql";
    /** */
    String DEFAULT_JDBC_ORACLE_HIBERNATE_DIALECT_VALUE         = "org.hibernate.dialect.Oracle10gDialect";
}