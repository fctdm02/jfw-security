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

import java.io.IOException;
import java.util.Map;

/**
 * 
 * @author tmyers
 * 
 */
public interface ICompuwareSecurityConfiguration {
		
    /**
     * Used to read/write the configuration properties from its backing store.
     * 
     * @param compuwareSecurityConfigurationPersistor
     */
	ICompuwareSecurityConfigurationPersistor getCompuwareSecurityConfigurationPersistor();
	
    /**
     * Used to read/write the configuration properties from its backing store.
     * 
     * @param compuwareSecurityConfigurationPersistor
     */
    void setCompuwareSecurityConfigurationPersistor(ICompuwareSecurityConfigurationPersistor compuwareSecurityConfigurationPersistor);

    
    
    /**
     * Reads configuration from backing store and performs an initial validation of the properties.
     * NOTE: Any changes made to the in-memory properties are discarded.
     * @throws IOException
     */
    void initialize()throws IOException;

    
    
    /**
     * Persists configuration properties for JDBC repository configuration (if non-null) 
     * and LDAP repository configuration (if non-null)
     * 
     * @throws IOException
     */
    void writeConfiguration() throws IOException;

	
	
    /**
     * 
     * @return The configuration properties from persistent storage (may be out-of-synch with what is in memory).
     */
    Map<String, String> getJdbcConfigurationFromPersistentStorage();    
	
	/**
	 * 
	 * @return The current set of configuration properties from memory (may not be persisted yet)
	 */
    Map<String, String> getJdbcConfiguration();
	
    /**
     * 
     * @param jdbcConfiguration The set of configuration properties to set in memory (does not do write)
     */
    void setJdbcConfiguration(Map<String, String> jdbcConfiguration);
	
	
	
    /**
     * 
     * @return The configuration properties from persistent storage (may be out-of-synch with what is in memory).
     */
    Map<String, String> getLdapConfigurationFromPersistentStorage();
    
	/**
	 * 
	 * @return The current set of configuration properties from memory (may not be persisted yet)
	 */
    Map<String, String> getLdapConfiguration();
 
    /**
     * 
     * @param ldapConfiguration The set of configuration properties to set in memory (does not do write)
     */
    void setLdapConfiguration(Map<String, String> ldapConfiguration);    
}