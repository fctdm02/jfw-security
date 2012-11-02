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
package com.compuware.frameworks.security.service.server.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.apache.log4j.Logger;

import com.compuware.frameworks.security.AbstractConfiguration;
import com.compuware.frameworks.security.CompuwareSecurityConfigurationUtil;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration;
import com.compuware.frameworks.security.persistence.PersistenceProvider;
import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.configuration.IConfigurationService;
import com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration;
import com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration;
import com.compuware.frameworks.security.service.api.configuration.exception.ConfigurationException;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;
import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityConfigurationChangedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySaveConfigurationErrorEvent;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityUser;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;
import com.compuware.frameworks.security.service.server.AbstractService;
import com.compuware.frameworks.security.service.server.ServiceProvider;
import com.compuware.frameworks.security.service.server.configuration.jdbc.JdbcConfigurationImpl;
import com.compuware.frameworks.security.service.server.configuration.ldap.LdapConfigurationImpl;

/**
 * 
 * @author tmyers
 * 
 */
public final class ConfigurationServiceImpl extends AbstractService implements IConfigurationService {

    /* */
    private static final int ZERO = 0;
    
    /* */
    private static final int ONE = 1;

    /* */
    private static final int TWO = 2;
    
    /* */
    private static final int FOUR = 4;
    
    /* */
    private static final int FIVE = 5;
    
    /* */
    private static final int EIGHT = 8;
    
    /* */
    private static final int SIXTEEN = 16;
    
    /* */
    private static final int TWENTY = 20;
    
    /* */
    private static final int THIRTY = 30;

    /* */
    private static final int ONE_HUNDRED = 100;

    /* */
    private static final int TWO_FIFTY_FIVE = 255;

    /* */
    private static final int FIVE_HUNDRED = 500;
    
    /* */
    private static final int ONE_THOUSAND = 1000;
    
    /* */
    private static final int TWENTY_EIGHT_EIGHT_HUNDRED = 28800;
    
    /* */
    private static final int SIXTY_THOUSAND = 60000;

    /* */
    private static final String SECURITY_COMPONENT = "frameworks.security";

    /* */
    private static final String SECURITY_COMPONENT_DISPLAY_NAME = "Common Components Security";

    /* */
    private static final String VERSION = "version=";

    /* */
    private static final String BUILD = "build=";

    /* */
    private static final String DELIMITER = " - ";
    
    
    /* */
    private final Logger logger = Logger.getLogger(ConfigurationServiceImpl.class);

    
	/* */
	private ICompuwareSecurityConfiguration coreConfiguration;
	    
	/**
	 * 
	 * @param coreConfiguration
	 * @param eventService
	 * @param auditService
	 * @param multiTenancyRealmDao
	 */
	public ConfigurationServiceImpl(
		ICompuwareSecurityConfiguration coreConfiguration,
		IEventService eventService,
		IAuditService auditService,
		IMultiTenancyRealmDao multiTenancyRealmDao) {
		super(auditService, eventService, multiTenancyRealmDao);
		setCoreConfiguration(coreConfiguration);
	}
	
	/*
	 * 
	 * @param coreConfiguration
	 */
	public void setCoreConfiguration(ICompuwareSecurityConfiguration coreConfiguration) {
		this.coreConfiguration = coreConfiguration;
	}
		
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getJdbcConfiguration()
     */
    public IJdbcConfiguration getJdbcConfiguration() {
        Map<String, String> jdbcConfigurationValues = this.coreConfiguration.getJdbcConfiguration();
        return new JdbcConfigurationImpl(jdbcConfigurationValues); 
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getLdapConfiguration()
     */
    public ILdapConfiguration getLdapConfiguration() {
        Map<String, String> ldapConfigurationValues = this.coreConfiguration.getLdapConfiguration();
        return new LdapConfigurationImpl(ldapConfigurationValues); 
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#storeConfiguration(com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration)
     */
    public void storeConfiguration(ILdapConfiguration ldapConfiguration) 
    throws 
        ValidationException, 
        ConfigurationException {
        this.storeConfiguration(ldapConfiguration, this.getJdbcConfiguration());
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#storeConfiguration(com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration)
     */
    public void storeConfiguration(IJdbcConfiguration jdbcConfiguration) 
    throws 
        ValidationException, 
        ConfigurationException {
        this.storeConfiguration(this.getLdapConfiguration(), jdbcConfiguration);
    }
            
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#storeConfiguration(com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration, com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration)
     */
    public void storeConfiguration(
        ILdapConfiguration ldapConfiguration, 
        IJdbcConfiguration jdbcConfiguration) 
    throws 
        ValidationException, 
        ConfigurationException {
        
        Map<String, String> persistedJdbcConfigurationMap = this.coreConfiguration.getJdbcConfigurationFromPersistentStorage();
        Map<String, String> newJdbcConfigurationMap = jdbcConfiguration.getAllConfigurationValues();
                
        Map<String, String> persistedLdapConfigurationMap = this.coreConfiguration.getLdapConfigurationFromPersistentStorage();
        Map<String, String> newLdapConfigurationMap = ldapConfiguration.getAllConfigurationValues();
        
        ValidationException validationException = null;
        ConfigurationException configurationException = null;
        
        try {
            Map<String, String> persistedConfigDelta = new TreeMap<String, String>();
            Map<String, String> newConfigDelta = new TreeMap<String, String>();
            
            boolean jdbcConfigChanged = false;
            if (!newJdbcConfigurationMap.toString().equalsIgnoreCase(persistedJdbcConfigurationMap.toString())) {
                
                validateJdbcConfiguration(newJdbcConfigurationMap);
                testJdbcConnection(newJdbcConfigurationMap);
                
                String persistedJdbcConfigurationVersion = persistedJdbcConfigurationMap.get(IJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY);
                String newJdbcConfigurationVersion = newJdbcConfigurationMap.get(IJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY);
                if (!persistedJdbcConfigurationVersion.equals(newJdbcConfigurationVersion)) {
                    
                    String reason = ValidationException.REASON_OPTIMISTIC_LOCK_FAILURE;
                    reason = reason.replace(ValidationException.TOKEN_ZERO, newJdbcConfigurationVersion);
                    reason = reason.replace(ValidationException.TOKEN_ONE, persistedJdbcConfigurationVersion);
                    throw new ValidationException(IJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY, reason);
                }
                
                newJdbcConfigurationVersion = Integer.toString(Integer.parseInt(newJdbcConfigurationVersion) + 1);    
                newJdbcConfigurationMap.put(IJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY, newJdbcConfigurationVersion);
                jdbcConfiguration.setConfigurationValue(IJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY, newJdbcConfigurationVersion);
                
                jdbcConfigChanged = true;
                persistedConfigDelta.putAll(persistedJdbcConfigurationMap);
                newConfigDelta.putAll(newJdbcConfigurationMap);
            }
            
            boolean ldapConfigChanged = false;
            if (!newLdapConfigurationMap.toString().equalsIgnoreCase(persistedLdapConfigurationMap.toString())) {

                String enableLdapAuthentication = newLdapConfigurationMap.get(ILdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY);
                if (enableLdapAuthentication.trim().equalsIgnoreCase("true")) {
                    validateLdapConfiguration(newLdapConfigurationMap);
                    testLdapConfiguration(newLdapConfigurationMap);
                }
                
                String persistedLdapConfigurationVersion = persistedLdapConfigurationMap.get(ILdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY);
                String newLdapConfigurationVersion = newLdapConfigurationMap.get(ILdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY);
                if (!persistedLdapConfigurationVersion.equals(newLdapConfigurationVersion)) {
                    
                    String reason = ValidationException.REASON_OPTIMISTIC_LOCK_FAILURE;
                    reason = reason.replace(ValidationException.TOKEN_ZERO, newLdapConfigurationVersion);
                    reason = reason.replace(ValidationException.TOKEN_ONE, persistedLdapConfigurationVersion);
                    throw new ValidationException(ILdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY, reason);
                }
                
                newLdapConfigurationVersion = Integer.toString(Integer.parseInt(newLdapConfigurationVersion) + 1);    
                newLdapConfigurationMap.put(ILdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY, newLdapConfigurationVersion);
                ldapConfiguration.setConfigurationValue(ILdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY, newLdapConfigurationVersion);
                
                ldapConfigChanged = true;
                persistedConfigDelta.putAll(persistedLdapConfigurationMap);
                newConfigDelta.putAll(newLdapConfigurationMap);
            }
            
            // Only write to disk if something actually changed.
            String eventDetails = null;
            if (jdbcConfigChanged || ldapConfigChanged) {
                
                eventDetails = "Configuration Changed: OLD:[" 
                   + persistedConfigDelta
                   + "], NEW:["
                   + newConfigDelta
                   + "]"; 
                
                try {
                    
                    // This is the heart of this whole method. 
                    logger.debug("Attempting to write configuration changes: " + newConfigDelta);
                    this.coreConfiguration.setJdbcConfiguration(newJdbcConfigurationMap);
                    this.coreConfiguration.setLdapConfiguration(newLdapConfigurationMap);
                    this.coreConfiguration.writeConfiguration();
                    logger.debug("Finished with write configuration changes: " + newConfigDelta);
                    
                } catch (IOException ioe) {
                    
                    //If there's an issue writing the file, roll back the changes to the in-memory maps.
                    this.coreConfiguration.setJdbcConfiguration(persistedJdbcConfigurationMap);
                    this.coreConfiguration.setLdapConfiguration(persistedLdapConfigurationMap);
                    throw new ConfigurationException("Could not store configuration changes: " 
                        + newConfigDelta 
                        + ", error: " 
                        + ioe.getMessage() 
                        + ", rolling back changes.", ioe);
                }
                
            } else {
                eventDetails = "No configuration changes detected, skipping writing configuration.";
                logger.debug(eventDetails);
            }

            // Create an audit event in the security DB for historical reporting.
            // With every audit event, an service event is fired and any listeners are notified.
            createAuditEvent(new CompuwareSecurityConfigurationChangedEvent(
                    persistedConfigDelta,
                    newConfigDelta,
                    this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                    this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                    this.getCurrentAuthenticationContext().getOriginatingHostname(),
                    this.getCurrentAuthenticationContext().getRealmName()));
                        
        } catch (ValidationException ve) {
            validationException = ve;
        } catch (ConfigurationException ce) {
            configurationException = ce;
        }
        
        // If an exception was thrown, revert the in-memory configuration back to the previously persisted values.
        if (validationException != null || configurationException != null) {

            this.coreConfiguration.setJdbcConfiguration(persistedJdbcConfigurationMap);
            this.coreConfiguration.setLdapConfiguration(persistedLdapConfigurationMap);

            String errorMessage = null;            
            if (validationException != null) {
                errorMessage = validationException.getMessage();
            } else {
                errorMessage = configurationException.getMessage();
            }
             
            String eventDetails = "Error occurred testing/storing new configuration: [" + errorMessage + "]";
            createAuditEvent(new CompuwareSecuritySaveConfigurationErrorEvent(
                    this.getCurrentAuthenticationContext().getUserObject().getUsername(),
                    this.getCurrentAuthenticationContext().getOriginatingIpAddress(),
                    this.getCurrentAuthenticationContext().getOriginatingHostname(),
                    eventDetails,
                    this.getCurrentAuthenticationContext().getRealmName()));
            
            if (validationException != null) {
                throw validationException;
            }
            throw configurationException;
        }
    }   

   /*
    * 
    * @param configuration
    * @throws ValidationException
    */
   private void validateJdbcConfiguration(Map<String, String> configuration) throws ValidationException {
       
       boolean hasSqlServerPropertyValues = false;
       boolean hasOraclePropertyValues = false;
       boolean hasDerbyPropertyValues = false;
       
       List<String> missingKeyList = new ArrayList<String>();
       missingKeyList.add(IJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_CONNECTION_STRING_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_TIMEOUT_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_SQL_DIALECT_KEY);       
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_ACQUIRE_INCREMENT_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_MIN_POOL_SIZE_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_INITIAL_POOL_SIZE_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_MAX_POOL_SIZE_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_MAX_CONNECTION_AGE_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_MAX_IDLE_TIME_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_MAX_IDLE_TIME_EXCESS_CONNECTIONS_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_IDLE_CONNECTION_TEST_PERIOD_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_TEST_CONNECTION_ON_CHECKIN_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_TEST_CONNECTION_ON_CHECKOUT_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_MAX_STATEMENTS_PER_CONNECTION_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_ACQUIRE_RETRY_ATTEMPTS_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_ACQUIRE_RETRY_DELAY_KEY);
       missingKeyList.add(IJdbcConfiguration.JDBC_C3P0_BREAK_AFTER_ACQUIRE_FAILURE_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_DIALECT_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_GENERATE_STATISTICS_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_SHOW_SQL_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_FORMAT_SQL_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_USE_SQL_COMMENTS_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_CACHE_USE_QUERY_CACHE_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_CACHE_USE_SECOND_LEVEL_CACHE_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_MAX_FETCH_DEPTH_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_DEFAULT_BATCH_FETCH_SIZE_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_JDBC_FETCH_SIZE_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_JDBC_BATCH_SIZE_KEY);
       missingKeyList.add(IJdbcConfiguration.HIBERNATE_JDBC_BATCH_VERSIONED_DATA_KEY);
       
       Iterator<String> iterator = configuration.keySet().iterator();
       while (iterator.hasNext()) {
           
           String key = iterator.next();
           String value = configuration.get(key);
           
           if (value != null) {
               value = value.trim();
           }
           
           if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY)) {
               
               int validLowerbound = ONE;
               int validUpperbound = Integer.MAX_VALUE;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
           
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY)) {
               
               Set<String> allowedValues = new HashSet<String>();
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_DRIVER_CLASS_NAME_VALUE);
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_ORACLE_DRIVER_CLASS_NAME_VALUE);
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_DERBY_DRIVER_CLASS_NAME_VALUE);
               validateEnumeratedStringValue(key, value, allowedValues, missingKeyList);
               if (value.equalsIgnoreCase(IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_DRIVER_CLASS_NAME_VALUE)) {
                   hasSqlServerPropertyValues = true;    
               } else if (value.equalsIgnoreCase(IJdbcConfiguration.DEFAULT_JDBC_ORACLE_DRIVER_CLASS_NAME_VALUE)) {
                   hasOraclePropertyValues = true;
               } else {
                   hasDerbyPropertyValues = true;
               }
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_CONNECTION_STRING_KEY)) {
               
               String sqlServerConnectionStringPrefix = IJdbcConfiguration.SQLSERVER_CONNECTION_STRING_PREFIX;
               String oracleServerConnectionStringPrefix = IJdbcConfiguration.ORACLE_CONNECTION_STRING_PREFIX; 
               String derbyConnectionStringPrefix = IJdbcConfiguration.DERBY_CONNECTION_STRING_PREFIX;
               
               Set<String> allowedPrefixes = new HashSet<String>();
               allowedPrefixes.add(sqlServerConnectionStringPrefix);
               allowedPrefixes.add(derbyConnectionStringPrefix);
               allowedPrefixes.add(oracleServerConnectionStringPrefix);
               validatePrefixedStringValue(key, value, allowedPrefixes, missingKeyList);
               if (value.toLowerCase().startsWith(sqlServerConnectionStringPrefix)) {
                   hasSqlServerPropertyValues = true;
               } else if (value.toLowerCase().startsWith(oracleServerConnectionStringPrefix)) {
                   hasOraclePropertyValues = true;
               } else {
                   hasDerbyPropertyValues = true;
               }
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY)) {
               
               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY)) {
               
               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_TIMEOUT_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = TWENTY_EIGHT_EIGHT_HUNDRED;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
                                             
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_SQL_DIALECT_KEY)) {
               
               Set<String> allowedValues = new HashSet<String>();
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_SQL_DIALECT_VALUE);
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_ORACLE_SQL_DIALECT_VALUE);
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_DERBY_SQL_DIALECT_VALUE);
               validateEnumeratedStringValue(key, value, allowedValues, missingKeyList);
               if (value.equalsIgnoreCase(IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_SQL_DIALECT_VALUE)) {
                   hasSqlServerPropertyValues = true;
               } else if (value.equalsIgnoreCase(IJdbcConfiguration.DEFAULT_JDBC_ORACLE_SQL_DIALECT_VALUE)) {
                   hasOraclePropertyValues = true;
               } else {
                   hasDerbyPropertyValues = true;
               }
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_DIALECT_KEY)) {
               
               Set<String> allowedValues = new HashSet<String>();
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_HIBERNATE_DIALECT_VALUE);
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_ORACLE_HIBERNATE_DIALECT_VALUE);
               allowedValues.add(IJdbcConfiguration.DEFAULT_JDBC_DERBY_HIBERNATE_DIALECT_VALUE);
               validateEnumeratedStringValue(key, value, allowedValues, missingKeyList);
               if (value.equalsIgnoreCase(IJdbcConfiguration.DEFAULT_JDBC_SQLSERVER_HIBERNATE_DIALECT_VALUE)) {
                   hasSqlServerPropertyValues = true;
               } else if (value.equalsIgnoreCase(IJdbcConfiguration.DEFAULT_JDBC_ORACLE_HIBERNATE_DIALECT_VALUE)) {
                   hasOraclePropertyValues = true;
               } else {
                   hasDerbyPropertyValues = true;
               }

           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_GENERATE_STATISTICS_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_SHOW_SQL_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_FORMAT_SQL_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_USE_SQL_COMMENTS_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_CACHE_USE_QUERY_CACHE_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_CACHE_USE_SECOND_LEVEL_CACHE_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_MAX_FETCH_DEPTH_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = FOUR;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_DEFAULT_BATCH_FETCH_SIZE_KEY)) {
               
               Set<String> allowedValues = new HashSet<String>();
               allowedValues.add(Integer.toString(FOUR));
               allowedValues.add(Integer.toString(EIGHT));
               allowedValues.add(Integer.toString(SIXTEEN));
               validateEnumeratedStringValue(key, value, allowedValues, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_JDBC_FETCH_SIZE_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = ONE_HUNDRED;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_JDBC_BATCH_SIZE_KEY)) {
               
               int validLowerbound = FIVE;
               int validUpperbound = THIRTY;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.HIBERNATE_JDBC_BATCH_VERSIONED_DATA_KEY)) {               
               
               this.validateBooleanValue(key, value, missingKeyList);
                                             
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_ACQUIRE_INCREMENT_KEY)) {
               
               int validLowerbound = ONE;
               int validUpperbound = ONE_HUNDRED;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_INITIAL_POOL_SIZE_KEY) 
                   || key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_MIN_POOL_SIZE_KEY)
                   || key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_MAX_POOL_SIZE_KEY)) {
               
               String minPoolSizeKey = IJdbcConfiguration.JDBC_C3P0_MIN_POOL_SIZE_KEY;
               String minPoolSizeValue = configuration.get(minPoolSizeKey);
               int minPoolSize = validateConstrainedIntegerValue(minPoolSizeKey, minPoolSizeValue, TWO, TWO_FIFTY_FIVE, missingKeyList);
                              
               String maxPoolSizeKey = IJdbcConfiguration.JDBC_C3P0_MAX_POOL_SIZE_KEY;
               String maxPoolSizeValue = configuration.get(maxPoolSizeKey);
               int maxPoolSize = validateConstrainedIntegerValue(maxPoolSizeKey, maxPoolSizeValue, TWO, TWO_FIFTY_FIVE, missingKeyList);
               
               String initialSizeKey = IJdbcConfiguration.JDBC_C3P0_INITIAL_POOL_SIZE_KEY;
               String initialSizeValue = configuration.get(maxPoolSizeKey);
               int initialPoolSize = validateConstrainedIntegerValue(initialSizeKey, initialSizeValue, TWO, TWO_FIFTY_FIVE, missingKeyList);

               if (minPoolSize > maxPoolSize) {
                   
                   String reason = ValidationException.REASON_MUST_BE_LESS_THAN;
                   reason = reason.replace(ValidationException.TOKEN_ZERO, IJdbcConfiguration.JDBC_C3P0_MIN_POOL_SIZE_KEY);
                   reason = reason.replace(ValidationException.TOKEN_ONE, IJdbcConfiguration.JDBC_C3P0_MAX_POOL_SIZE_KEY);
                   throw new ValidationException(IJdbcConfiguration.JDBC_C3P0_MIN_POOL_SIZE_KEY, reason);
               }
               
               if (initialPoolSize < minPoolSize || initialPoolSize > maxPoolSize) {
                   
                   String reason = ValidationException.REASON_MUST_BE_LESS_THAN;
                   reason = reason.replace(ValidationException.TOKEN_ZERO, IJdbcConfiguration.JDBC_C3P0_MIN_POOL_SIZE_KEY);
                   reason = reason.replace(ValidationException.TOKEN_ONE, IJdbcConfiguration.JDBC_C3P0_MAX_POOL_SIZE_KEY);
                   throw new ValidationException(IJdbcConfiguration.JDBC_C3P0_INITIAL_POOL_SIZE_KEY, reason);
               }
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_MAX_CONNECTION_AGE_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = ONE_THOUSAND;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
                              
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_MAX_IDLE_TIME_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = ONE_THOUSAND;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_MAX_IDLE_TIME_EXCESS_CONNECTIONS_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = ONE_THOUSAND;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_IDLE_CONNECTION_TEST_PERIOD_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = ONE_THOUSAND;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_TEST_CONNECTION_ON_CHECKIN_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_TEST_CONNECTION_ON_CHECKOUT_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_MAX_STATEMENTS_PER_CONNECTION_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = TWO_FIFTY_FIVE;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_ACQUIRE_RETRY_ATTEMPTS_KEY)) {

               int validLowerbound = ONE;
               int validUpperbound = TWO_FIFTY_FIVE;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_ACQUIRE_RETRY_DELAY_KEY)) {

               int validLowerbound = FIVE_HUNDRED;
               int validUpperbound = SIXTY_THOUSAND;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(IJdbcConfiguration.JDBC_C3P0_BREAK_AFTER_ACQUIRE_FAILURE_KEY)) {
               
               this.validateBooleanValue(key, value, missingKeyList);
               
           }
       }
       
       if (hasSqlServerPropertyValues && hasDerbyPropertyValues && hasOraclePropertyValues) {
           throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_INVALID_MIXTURE_OF_DATABASE_TYPE_FIELDS);
       }
       
       validateMissingKeyList(missingKeyList);
   }

   /*
    * 
    * @param configuration
    * @throws ValidationException
    */
   private void validateLdapConfiguration(Map<String, String> configuration) throws ValidationException {
    
       List<String> missingKeyList = new ArrayList<String>();
       missingKeyList.add(ILdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY);
       missingKeyList.add(ILdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_TYPE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_URL_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_REFERRAL_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_TIMEOUT_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USE_TLS_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_PAGE_SIZE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY);
       missingKeyList.add(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY);
       
              
       Iterator<String> iterator = configuration.keySet().iterator();
       while (iterator.hasNext()) {
           
           String key = iterator.next();
           String value = configuration.get(key);
           
           if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY)) {
               
               int validLowerbound = ONE;
               int validUpperbound = Integer.MAX_VALUE;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY)) {
               
               validateBooleanValue(key, value, missingKeyList);

           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_TYPE_KEY)) {

               Set<String> allowedValues = new HashSet<String>();
               allowedValues.add(ILdapConfiguration.APACHEDS);
               allowedValues.add(ILdapConfiguration.ACTIVEDIR);
               validateEnumeratedStringValue(key, value, allowedValues, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_URL_KEY)) {
               
               Set<String> allowedPrefixes = new HashSet<String>();
               allowedPrefixes.add("ldap://");
               allowedPrefixes.add("ldaps://");
               validatePrefixedStringValue(key, value, allowedPrefixes, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY)) {
               
               int minLength = ONE;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)) {
               
               int minLength = ONE;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_REFERRAL_KEY)) {
               
               Set<String> allowedValues = new HashSet<String>();
               allowedValues.add(ILdapConfiguration.LDAP_REFERRAL_FOLLOW);
               allowedValues.add(ILdapConfiguration.LDAP_REFERRAL_IGNORE);
               allowedValues.add(ILdapConfiguration.LDAP_REFERRAL_THROW);
               validateEnumeratedStringValue(key, value, allowedValues, missingKeyList);
                              
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY)) {
               
               int validLowerbound = ZERO;
               int validUpperbound = TWENTY;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_TIMEOUT_KEY)) {
               
               int validLowerbound = ONE_THOUSAND;
               int validUpperbound = SIXTY_THOUSAND;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USE_TLS_KEY)) {
               
               validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY)) {
               
               validateBooleanValue(key, value, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_PAGE_SIZE_KEY)) {
               
               int validLowerbound = ONE_HUNDRED;
               int validUpperbound = ONE_THOUSAND;
               validateConstrainedIntegerValue(key, value, validLowerbound, validUpperbound, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY)) {
               
               int minLength = ONE;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY)) {
                              
               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY)) {

               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY)) {

               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY)) {

               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);               
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY)) {

               int minLength = TWO;
               int maxLength = TWO_FIFTY_FIVE;
               validateParenthesizedStringValue(key, value, minLength, maxLength, missingKeyList);               
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY)) {

               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);                              
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY)) {
               
               int minLength = TWO;
               int maxLength = TWO_FIFTY_FIVE;
               validateParenthesizedStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY)) {
               
               int minLength = ONE;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);               
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY)) {
                              
               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);                              
                              
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY)) {

               int minLength = ZERO;
               int maxLength = TWO_FIFTY_FIVE;
               validateStringValue(key, value, minLength, maxLength, missingKeyList);
               
           } else if (key.equalsIgnoreCase(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY)) {

               int minLength = TWO;
               int maxLength = TWO_FIFTY_FIVE;
               validateParenthesizedStringValue(key, value, minLength, maxLength, missingKeyList);
               
           }
       }
       
       validateMissingKeyList(missingKeyList);
   }

   /*
    * 
    * @param missingKeyList
    * @throws ValidationException
    */
   private void validateMissingKeyList(List<String> missingKeyList) throws ValidationException {
       if (missingKeyList.size() > 0) {
           
           String reason = ValidationException.REASON_MISSING_KEY_VALUE_PAIRS;
           reason = reason.replace(ValidationException.TOKEN_ZERO, missingKeyList.toString());
           throw new ValidationException(ValidationException.FIELD_ALL, reason);
       }
   }

   /*
    * 
    * @param key
    * @param value
    * @param missingKeyList
    * @throws ValidationException
    */
   private void validateBooleanValue(String key, String value, List<String> missingKeyList) throws ValidationException {
       Set<String> allowedValues = new HashSet<String>();
       allowedValues.add("true");
       allowedValues.add("false");
       validateEnumeratedStringValue(key, value, allowedValues, missingKeyList);
   }

   /*
    * 
    * @param key
    * @param value
    * @param allowedPrefixes
    * @param missingKeyList
    * @throws ValidationException
    */
   private void validatePrefixedStringValue(String key, String value, Set<String> allowedPrefixes, List<String> missingKeyList) throws ValidationException {
       boolean validValue = false;
       Iterator<String> iterator = allowedPrefixes.iterator();
       while (iterator.hasNext()) {
           String prefix = iterator.next();
           if (value.startsWith(prefix)) {
               validValue = true;
               break;
           }
       }
       if (!validValue) {
           String reason = ValidationException.REASON_INVALID_PREFIX;
           reason = reason.replace(ValidationException.TOKEN_ZERO, value);
           reason = reason.replace(ValidationException.TOKEN_ONE, allowedPrefixes.toString());
           throw new ValidationException(key, reason);
       }
       missingKeyList.remove(key);
   }
   
   /*
    * @param key
    * @param value
    * @param allowedValues
    * @param missingKeyList
    * @throws ValidationException
    */
   private void validateEnumeratedStringValue(String key, String value, Set<String> allowedValues, List<String> missingKeyList) throws ValidationException {
       if (!allowedValues.contains(value)) {
           String reason = ValidationException.REASON_INVALID_ENUMERATED_VALUE;
           reason = reason.replace(ValidationException.TOKEN_ZERO, value);
           reason = reason.replace(ValidationException.TOKEN_ONE, allowedValues.toString());
           throw new ValidationException(key, reason);
       }
       missingKeyList.remove(key);
   }
   
   /*
    * @param key
    * @param value
    * @param minLength
    * @param maxLength
    * @param missingKeyList
    * @throws ValidationException
    */
   private void validateStringValue(String key, String value, int minLength, int maxLength, List<String> missingKeyList) throws ValidationException {
       if (value.trim().length() < minLength || value.trim().length() > maxLength) {
           String reason = ValidationException.REASON_INVALID_STRING_LENGTH;
           reason = reason.replace(ValidationException.TOKEN_ZERO, Integer.toString(minLength));
           reason = reason.replace(ValidationException.TOKEN_ONE, Integer.toString(maxLength));
           throw new ValidationException(key, reason);
       }
       missingKeyList.remove(key);
   }

   /*
    * @param key
    * @param value
    * @param minLength
    * @param maxLength
    * @param missingKeyList
    * @throws ValidationException
    */
   private void validateParenthesizedStringValue(String key, String value, int minLength, int maxLength, List<String> missingKeyList) throws ValidationException {
       
       validateStringValue(key, value, minLength, maxLength, missingKeyList);
       
       if (!value.startsWith("(") || !value.endsWith(")")) {
           throw new ValidationException(key, ValidationException.REASON_INVALID_PARENTHESIZED_VALUE);
       }
       
       missingKeyList.remove(key);
   }
 
   /*
    * @param key
    * @param value
    * @param validLowerbound
    * @param validUpperbound
    * @param missingKeyList
    * @throws ValidationException
    */
   private int validateConstrainedIntegerValue(String key, String value, int validLowerbound, int validUpperbound, List<String> missingKeyList) throws ValidationException {
 
       Integer intValue = Integer.valueOf(0);
       boolean invalidValue = false;
       if (value.trim().length() == 0) {
           invalidValue = true;
       } else {
           try {
               intValue = Integer.parseInt(value);
               if (intValue.intValue() < validLowerbound || intValue.intValue() > validUpperbound) {
                   invalidValue = true;
               }
           } catch (NumberFormatException nfe) {
               invalidValue = true;
           }
       }
       if (invalidValue) {
           String reason = ValidationException.REASON_MUST_BE_BETWEEN;
           reason = reason.replace(ValidationException.TOKEN_ZERO, Integer.toString(validLowerbound));
           reason = reason.replace(ValidationException.TOKEN_ONE, Integer.toString(validUpperbound));
           throw new ValidationException(key, reason);
       }
       missingKeyList.remove(key);
       return intValue.intValue();
   }
   
   /*
    * 
    * @param ldapConfiguration
    * @throws ValidationException
    */
   private void testLdapConfiguration(Map<String, String> ldapConfiguration) throws ValidationException {
       
       MultiTenancyRealm multiTenancyRealm = getMultiTenancyRealmForSecurityContext();
       
       ILdapSearchService ldapSearchService = ServiceProvider.getInstance().getLdapSearchService();
       try {
           ldapSearchService.testLdapConnection(
               ldapConfiguration.get(ILdapConfiguration.LDAP_URL_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY), 
               new ClearTextPassword(ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_KEY), 
               Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY)), 
               Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_TIMEOUT_KEY)), 
               Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_USE_TLS_KEY)),
               Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY)),
               multiTenancyRealm);
       } catch (InvalidConnectionException invalidConnectionException) {
           throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_COULD_NOT_CONNECT_TO_LDAP, invalidConnectionException);
       } catch (InvalidCredentialsException invalidCredentialsException) {
           throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_COULD_NOT_AUTHENTICATE_TO_LDAP, invalidCredentialsException);
       }
       
       try {
           List<ShadowSecurityUser> allLdapUsers = ldapSearchService.testGetAllLdapUsers(
               ldapConfiguration.get(ILdapConfiguration.LDAP_URL_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY), 
               new ClearTextPassword(ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_KEY), 
               Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY)), 
               Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_TIMEOUT_KEY)),
               Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_USE_TLS_KEY)),
               Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY)),
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY), 
               multiTenancyRealm);
           
           // Assume that an empty list is invalid.
           if (allLdapUsers.size() == 0) {
               String reason = ValidationException.REASON_NO_LDAP_USERS_FOUND_WITH_GIVEN_BASE_AND_FILTER;
               reason = reason.replace(ValidationException.TOKEN_ZERO, ldapConfiguration.get(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY));
               reason = reason.replace(ValidationException.TOKEN_ONE, ldapConfiguration.get(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY));
               throw new ValidationException(ValidationException.FIELD_ALL, reason);
           }
           
           ShadowSecurityUser shadowSecurityUser = allLdapUsers.get(0);
           List<ShadowSecurityGroup> userLdapGroups = ldapSearchService.testGetLdapGroupsForLdapUser(
               ldapConfiguration.get(ILdapConfiguration.LDAP_URL_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY), 
               new ClearTextPassword(ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_KEY), 
               Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY)), 
               Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_TIMEOUT_KEY)),
               Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_USE_TLS_KEY)),
               Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY)),
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY), 
               shadowSecurityUser.getUsername(), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY),
               ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY), 
               multiTenancyRealm);
           
           // Assume that an empty list is invalid.
           if (userLdapGroups.size() == 0) {
               
               logger.debug("No LDAP groups for LDAP user: [" 
                   + shadowSecurityUser
                   + "] were found using user groups search base: [" 
                   + ldapConfiguration.get(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY)
                   + "], user groups search filter: ["
                   + ldapConfiguration.get(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY)
                   + "] for LDAP server URL: "
                   + ldapConfiguration.get(ILdapConfiguration.LDAP_URL_KEY)
                   + "], authorization may not work properly as a result...");
           }
                      
           List<ShadowSecurityGroup> allLdapGroups = ldapSearchService.testGetAllLdapGroups(
               ldapConfiguration.get(ILdapConfiguration.LDAP_URL_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY), 
               new ClearTextPassword(ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_KEY), 
               Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY)), 
               Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_TIMEOUT_KEY)),
               Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_USE_TLS_KEY)),
               Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY)),
               ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY), 
               ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY), 
               multiTenancyRealm);
               
           // Assume that an empty list is invalid.
           if (allLdapGroups.size() == 0) {
               String reason = ValidationException.REASON_NO_LDAP_GROUPS_FOUND_WITH_GIVEN_BASE_AND_FILTER;
               reason = reason.replace(ValidationException.TOKEN_ZERO, ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_BASE_KEY));
               reason = reason.replace(ValidationException.TOKEN_ONE, ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_LIST_SEARCH_FILTER_KEY));
               throw new ValidationException(ValidationException.FIELD_ALL, reason);
           }
           
           // APMOSECURITY-150: Ensure that the currently logged in local administrator's username does not 
           // already exist in LDAP (because if it, they would not be able to login, per APMOSECURITY-54.)
           AbstractUser abstractUser = this.getCurrentlyAuthenticatedUser();
           if (abstractUser instanceof SecurityUser) {               
               String currentlyAuthenticationUsername = this.getCurrentlyAuthenticatedUser().getUsername();
               try {
                   ldapSearchService.testGetLdapUserWithGroups(
                   ldapConfiguration.get(ILdapConfiguration.LDAP_URL_KEY), 
                   ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY), 
                   new ClearTextPassword(ldapConfiguration.get(ILdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)), 
                   ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_KEY), 
                   Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_REFERRAL_LIMIT_KEY)), 
                   Integer.parseInt(ldapConfiguration.get(ILdapConfiguration.LDAP_TIMEOUT_KEY)),
                   Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_USE_TLS_KEY)),
                   Boolean.parseBoolean(ldapConfiguration.get(ILdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY)),
                   ldapConfiguration.get(ILdapConfiguration.LDAP_USER_USERNAME_ATTRIBUTE_KEY), 
                   ldapConfiguration.get(ILdapConfiguration.LDAP_USER_EMAIL_ADDRESS_ATTRIBUTE_KEY), 
                   ldapConfiguration.get(ILdapConfiguration.LDAP_USER_FIRST_NAME_ATTRIBUTE_KEY), 
                   ldapConfiguration.get(ILdapConfiguration.LDAP_USER_LAST_NAME_ATTRIBUTE_KEY), 
                   ldapConfiguration.get(ILdapConfiguration.LDAP_USER_SEARCH_BASE_KEY), 
                   ldapConfiguration.get(ILdapConfiguration.LDAP_USER_SEARCH_FILTER_KEY), 
                   currentlyAuthenticationUsername, 
                   ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_GROUPNAME_ATTRIBUTE_KEY),
                   ldapConfiguration.get(ILdapConfiguration.LDAP_GROUP_DESCRIPTION_ATTRIBUTE_KEY),
                   ldapConfiguration.get(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_BASE_KEY),
                   ldapConfiguration.get(ILdapConfiguration.LDAP_USER_GROUPS_SEARCH_FILTER_KEY),
                   multiTenancyRealm);
                   throw new ValidationException("Cannot enable LDAP Configuration because an LDAP user exists with the same username as the currently logged in administrator: [" + currentlyAuthenticationUsername + "]. Please create and use a differently named local security user administrator, delete the current user and try again.");
              } catch (ObjectNotFoundException e) {
              }
           }
           
       } catch (InvalidConnectionException invalidConnectionException) {
           throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_COULD_NOT_CONNECT_TO_LDAP, invalidConnectionException);
       } catch (InvalidCredentialsException invalidCredentialsException) {
           throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_COULD_NOT_AUTHENTICATE_TO_LDAP, invalidCredentialsException);
       }
   }
   
   /*
    * 
    * @param map
    * @throws ValidationException
    */
   private void testJdbcConnection(Map<String, String> map) throws ValidationException {
              
       try {
           
           IJdbcConfiguration jdbcConfiguration = new JdbcConfigurationImpl(map);
           
           // Get the built connection string and derived driver class name.
           String driverClassName = jdbcConfiguration.getConfigurationValue(IJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY);
           String jdbcConnectionString = jdbcConfiguration.getConfigurationValue(IJdbcConfiguration.JDBC_CONNECTION_STRING_KEY);
           String username = jdbcConfiguration.getConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY);
           String password = jdbcConfiguration.getConfigurationValue(IJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY);
           
           // Finally, test the connection.
           PersistenceProvider.getInstance().testJdbcConnection(
               driverClassName, 
               jdbcConnectionString, 
               username, 
               password);
           
       } catch (InvalidCredentialsException invalidCredentialsException) {
           throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_COULD_NOT_CONNECT_TO_DATABAE, invalidCredentialsException);
       } catch (Exception e) {
           throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_COULD_NOT_CONNECT_TO_DATABAE, e);
       }       
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getDefaultJdbcConfiguration()
    */
   public Map<String, String> getDefaultJdbcConfiguration() {
       return this.coreConfiguration.getCompuwareSecurityConfigurationPersistor().getDefaultJdbcConfiguration();
   }
 
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getDefaultLdapConfiguration()
    */
   public Map<String, String> getDefaultLdapConfiguration() {
       return this.coreConfiguration.getCompuwareSecurityConfigurationPersistor().getDefaultLdapConfiguration();
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getDefaultApacheDsLdapConfiguration()
    */
   public Map<String, String> getDefaultApacheDsLdapConfiguration() {
       Map<String, String> map = new TreeMap<String, String>();
       map.putAll(AbstractConfiguration.DEFAULT_APACHEDS_LDAP_PROPERTIES);
       return map;
   }

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getDefaultActiveDirectoryLdapConfiguration()
    */
   public Map<String, String> getDefaultActiveDirectoryLdapConfiguration() {
       Map<String, String> map = new TreeMap<String, String>();
       map.putAll(AbstractConfiguration.DEFAULT_ACTIVEDIR_LDAP_PROPERTIES);
       return map;
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getDefaultEmbeddedDerbyJdbcConfiguration()
    */
   public Map<String, String> getDefaultEmbeddedDerbyJdbcConfiguration() {
       Map<String, String> map = new TreeMap<String, String>();
       map.putAll(AbstractConfiguration.DEFAULT_DERBY_JDBC_PROPERTIES);
       return map;
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getDefaultSqlServerJdbcConfiguration()
    */
   public Map<String, String> getDefaultSqlServerJdbcConfiguration() {
       Map<String, String> map = new TreeMap<String, String>();
       map.putAll(AbstractConfiguration.DEFAULT_SQLSERVER_JDBC_PROPERTIES);
       return map;
   }

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getSecurityServerOperatingSystemName()
    */
   public String getSecurityServerOperatingSystemName() {
       return System.getProperty(OS_NAME_SYSTEM_PROPERTY);
   }

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getSupportedDatabaseTypes()
    */
   public List<String> getSupportedDatabaseTypes() {
       List<String> list = new ArrayList<String>();
       list.add(IJdbcConfiguration.SQLSERVER);
       list.add(IJdbcConfiguration.ORACLE);
       list.add(IJdbcConfiguration.DERBY);
       return list;
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getSupportedDatabaseAuthenticationTypes(java.lang.String)
    */
   public List<String> getSupportedDatabaseAuthenticationTypes(String databaseType) {
       
       List<String> supportedAuthenticationTypesList = new ArrayList<String>();
       supportedAuthenticationTypesList.add(IJdbcConfiguration.LOCAL_DB_AUTH_TYPE);
       
       String osName = this.getSecurityServerOperatingSystemName();
       if (osName.startsWith(OS_NAME_WINDOWS) && (databaseType.equals(IJdbcConfiguration.SQLSERVER))) {
           supportedAuthenticationTypesList.add(IJdbcConfiguration.WINDOWS_DOMAIN_DB_AUTH_TYPE);
           supportedAuthenticationTypesList.add(IJdbcConfiguration.WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE);
       }
       
       return supportedAuthenticationTypesList;
   }

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getSupportedLdapEncryptionMethods()
    */
	public List<String> getSupportedLdapEncryptionMethods() {
       List<String> supportedLdapEncryptionMethodsList = new ArrayList<String>();
       supportedLdapEncryptionMethodsList.add(ILdapConfiguration.LDAP_ENCRYPTION_METHOD_NONE);
       supportedLdapEncryptionMethodsList.add(ILdapConfiguration.LDAP_ENCRYPTION_METHOD_SSL);
       supportedLdapEncryptionMethodsList.add(ILdapConfiguration.LDAP_ENCRYPTION_METHOD_TLS);
       return supportedLdapEncryptionMethodsList;
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getSupportedLdapDirectories()
    */
	public List<String> getSupportedLdapDirectories() {
       List<String> supportedLdapDirectoriesList = new ArrayList<String>();
       supportedLdapDirectoriesList.add(ILdapConfiguration.ACTIVEDIR);
       supportedLdapDirectoriesList.add(ILdapConfiguration.APACHEDS);
       supportedLdapDirectoriesList.add(ILdapConfiguration.OTHER);
       return supportedLdapDirectoriesList;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getSecurityServerOperatingSystemInfo()
	 */
    public String getSecurityServerOperatingSystemInfo() {
        StringBuilder sb = new StringBuilder(256);
        sb.append(System.getProperty(OS_ARCH_SYSTEM_PROPERTY));
        sb.append(" ");
        sb.append(System.getProperty(OS_NAME_SYSTEM_PROPERTY));
        sb.append(" ");
        sb.append(System.getProperty(OS_VERSION_SYSTEM_PROPERTY));
        return sb.toString();
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getSecurityServerJavaVirtualMachineInfo()
     */
    public String getSecurityServerJavaVirtualMachineInfo() {
        StringBuilder sb = new StringBuilder(256);
        sb.append(System.getProperty(JVM_VENDOR_SYSTEM_PROPERTY));
        sb.append(" ");
        sb.append(System.getProperty(JVM_NAME_SYSTEM_PROPERTY));
        sb.append(" ");
        sb.append(System.getProperty(JVM_VERSION_SYSTEM_PROPERTY));
        return sb.toString();
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.configuration.IConfigurationService#getSecurityServerReleaseInformation()
     */
    public String getSecurityServerReleaseInformation() {
                
        File compuwareSecurityConfigurationDir = CompuwareSecurityConfigurationUtil.getCompuwareSecurityConfigurationDir();
        File parentDir = compuwareSecurityConfigurationDir.getParentFile();
        File grandParentDir = parentDir.getParentFile();
        File versionXmlFile = new File(grandParentDir, "version.xml");
        
        String product = SECURITY_COMPONENT_DISPLAY_NAME;
        String version = null;
        String build = null;
        
        /*
         * version.xml:     C:\Program Files\Compuware\Common Components\cc\eclipse\version.xml
         * jdbc properties: C:\Program Files\Compuware\Common Components\cc\eclipse\workspace\com.compuware.frameworks.security\compuwareSecurityJdbcConfiguration.properties
         */

        /*<?xml version="1.0" encoding="UTF-8" ?> 
        <product 
           name="security.server.kit" 
           version="5.1.0" 
           build="342" 
           tag="201201302017_Security_Server_5_2_0_342_trunk" 
           serviceName="CompuwareSecurityServer_1"
                     1         2         3         4
           01234567890123456789012345678901234567890123456789
           serviceDisplay="Compuware Security Server" 
           userDirectory="C:\Program Files\Compuware\Common Components\cc\eclipse">
           <component name="frameworks.security" version="5.0.0" build="718" tag="201201301931_security_2_0_0_718_trunk" /> 
           <component name="${product(name)}" version="${product(version)}" build="${product(build)}" tag="${product(tag)}" /> 
           <component name="frameworks.installer.ga" version="5.1.0" build="276" tag="201201192004_v050100_GA_276_INSTALLER_branch" /> 
        </product>*/
        
        String securityServerReleaseInformation = null;
        if (versionXmlFile.exists()) {
           BufferedReader in = null;                  
           try {
              in = new BufferedReader(new FileReader(versionXmlFile), 512);
              String line = in.readLine();
              while (line != null && (product == null || version == null || build == null)) {
                 line = in.readLine();
                 
                 int index = line.indexOf(SECURITY_COMPONENT);
                 if (index >= 0) {
	                 index = line.indexOf(VERSION);
	                 if (version == null && index >= 0) {
	                     int length = VERSION.length();
	                     int endIndex = line.indexOf('"', index+length+1);
	                     version = line.substring(index+length+1, endIndex);
	                 }
	
	                 index = line.indexOf(BUILD);
	                 if (build == null && index >= 0) {
	                     int length = BUILD.length();
	                     int endIndex = line.indexOf('"', index+length+1);
	                     build = line.substring(index+length+1, endIndex);
	                 }
                 }
              }
              
              StringBuilder sb = new StringBuilder(256);
              sb.append(product);
              sb.append(DELIMITER);
              sb.append(version);
              sb.append(DELIMITER);
              sb.append(build);        
              securityServerReleaseInformation = sb.toString();
              
           } catch (IOException ioe) {
              throw new ServiceException("Could not read: [" + versionXmlFile.getAbsolutePath() + "], error: [" + ioe.getMessage() + "].", ioe);
           } finally {
              try {
                 if (in != null) {
                    in.close();
                 }
              } catch (Exception ioe2) {
                 throw new ServiceException("Could not close resources for: [" + versionXmlFile.getAbsolutePath() + "], error: [" + ioe2.getMessage() + "].", ioe2);
              }               
           }   
        } else {
            securityServerReleaseInformation = "Security server version.xml file not found: [" + versionXmlFile.getAbsolutePath() + "].";
        }
        
        return securityServerReleaseInformation;
    }
}