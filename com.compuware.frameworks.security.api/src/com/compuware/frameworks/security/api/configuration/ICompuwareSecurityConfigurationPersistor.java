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
public interface ICompuwareSecurityConfigurationPersistor {

    /**
     * 
     * @return Map<String, String>
     * @throws IOException
     */
    Map<String, String> getDefaultJdbcConfiguration();
    
	/**
	 * 
	 * @return Map<String, String>
	 * @throws IOException
	 */
    Map<String, String> readJdbcConfiguration() throws IOException;

    /**
     * 
     * @param jdbcConfiguration
     * @throws IOException
     */
    void writeJdbcConfiguration(Map<String, String> jdbcConfiguration) throws IOException;
    
    
    
    /**
     * 
     * @return Map<String, String>
     * @throws IOException
     */
    Map<String, String> getDefaultLdapConfiguration();
    
	/**
	 * 
	 * @return Map<String, String>
	 * @throws IOException
	 */
    Map<String, String> readLdapConfiguration() throws IOException;

    /**
     * 
     * @param ldapConfiguration
     * @throws IOException
     */
    void writeLdapConfiguration(Map<String, String> ldapConfiguration) throws IOException;    
}