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
package com.compuware.frameworks.security;

import java.io.File;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPropertyPlaceholderConfigurer;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityJdbcConfiguration;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityLdapConfiguration;

/**
 * 
 * @author tmyers
 * 
 */
public class CompuwareSecurityPropertyPlaceholderConfigurer extends PropertyPlaceholderConfigurer implements ICompuwareSecurityConfigurationPropertyPlaceholderConfigurer {

    /* */
    private Logger logger = Logger.getLogger(CompuwareSecurityPropertyPlaceholderConfigurer.class);
    
    /* */
    private ICompuwareSecurityConfiguration compuwareSecurityConfiguration;
    
    /**
     * 
     * @param compuwareSecurityConfiguration
     */
    public CompuwareSecurityPropertyPlaceholderConfigurer(ICompuwareSecurityConfiguration compuwareSecurityConfiguration) {
        setCompuwareSecurityConfiguration(compuwareSecurityConfiguration);
    }

    /**
     * 
     * @param compuwareSecurityConfiguration
     */
    public final void setCompuwareSecurityConfiguration(ICompuwareSecurityConfiguration compuwareSecurityConfiguration) {
        this.compuwareSecurityConfiguration = compuwareSecurityConfiguration;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPropertyPlaceholderConfigurer#resolvePlaceholder(java.lang.String)
     */
    public final String resolvePlaceholder(String key) {
        return this.resolvePlaceholder(key, new Properties(), PropertyPlaceholderConfigurer.SYSTEM_PROPERTIES_MODE_OVERRIDE);
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.beans.factory.config.PropertyPlaceholderConfigurer#resolvePlaceholder(java.lang.String, java.util.Properties, int)
     */
    public final String resolvePlaceholder(String key, Properties parmProperties, int systemPropertiesMode) {
        
        String value = null;
        String displayValue = null;
        String disableSystemPropertyOverride = System.getProperty("disableSystemPropertyOverride");
        if (disableSystemPropertyOverride == null || disableSystemPropertyOverride.toLowerCase().trim().equals("false")) {
            value = super.resolvePlaceholder(key, parmProperties, systemPropertiesMode);
        }        
        if (value == null) {
            
            Map<String, String> properties = null;
            if (key.toLowerCase().startsWith("jdbc.") || key.toLowerCase().startsWith("hibernate.")) {
                
                properties = this.compuwareSecurityConfiguration.getJdbcConfiguration();
                value = properties.get(key);
                
                if (key.equalsIgnoreCase(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY)) {
                    displayValue = "[PROTECTED]";
                } else {
                    displayValue = value;
                }
                
            } else if (key.toLowerCase().indexOf("ldap.") >= 0) {
                
                properties = this.compuwareSecurityConfiguration.getLdapConfiguration();
                
                value = CompuwareSecurityConfigurationUtil.getLdapPropertyValue(properties, key);
                                                
                if (key.equalsIgnoreCase(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)) {
                    displayValue = "[PROTECTED]";
                } else {
                    displayValue = value;
                }
                
            } else if (key.toLowerCase().equals("ehcache.configlocation")) {
                
                File compuwareSecurityConfigurationDir = CompuwareSecurityConfigurationUtil.getCompuwareSecurityConfigurationDir();
                File ehCacheConfigurationFile = new File(compuwareSecurityConfigurationDir.getAbsolutePath() + File.separator + "ehcache.xml");
                if (ehCacheConfigurationFile.exists()) {
                    value = "file:" + ehCacheConfigurationFile.getAbsolutePath();
                } else {
                    value = "classpath:ehcache.xml";
                }
                displayValue = value;
            }
            logger.debug("Resolved property: [" + key + "] to: [" + displayValue + "] via CompuwareSecurityConfiguration.");       
        } else {
            logger.debug("Resolved property: [" + key + "] to: [" + value + "] via System Property.");
        }
        
        return value;
    }
}