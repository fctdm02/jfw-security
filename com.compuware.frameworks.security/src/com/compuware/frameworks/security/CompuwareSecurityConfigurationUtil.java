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

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Map;

import org.apache.log4j.Logger;

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityLdapConfiguration;

/**
 * 
 * @author tmyers
 */
public final class CompuwareSecurityConfigurationUtil {
    
    /* */
    private static final Logger logger = Logger.getLogger(CompuwareSecurityConfigurationUtil.class);
    
    /**
     * 
     * @return
     */
    public static File getCompuwareSecurityConfigurationDir() {

        URL osgiInstanceAreaToUse = null;
        
        try {
            String configDirBase = null;
            
            //URL osgiInstanceArea = JFWUtil.getInstanceArea();
            URL osgiInstanceArea = null;           
            URL osgiInstanceAreaDefault = null;
            
            if (osgiInstanceArea != null) {
                logger.debug("'osgi.instance.area' value is: " + osgiInstanceArea);
                osgiInstanceAreaToUse = osgiInstanceArea;
            } else {
            	//osgiInstanceAreaDefault = JFWUtil.getInstanceAreaDefault();
                osgiInstanceAreaDefault = null;
                if (osgiInstanceAreaDefault != null) {
                    logger.debug("'osgi.instance.area.default' value is: " + osgiInstanceAreaDefault);
                    osgiInstanceAreaToUse = osgiInstanceAreaDefault;
                }
            }
            
            if (osgiInstanceAreaToUse != null) {
                String errorMessage = "Could not decode OSGi instance area: [" + osgiInstanceAreaToUse + "], error: ";
                try {
                    configDirBase = URLDecoder.decode(osgiInstanceAreaToUse.toURI().toString(), "UTF-8").substring("file:".length());    
                } catch (URISyntaxException e) {
                    logger.error(errorMessage + e.getMessage());
                } catch (UnsupportedEncodingException e) {
                    logger.error(errorMessage + e.getMessage());
                }
            }
                    
            if (configDirBase == null) {
                configDirBase = new File(".").getAbsolutePath();
                logger.error("Could not use either 'osgi.instance.area' and 'osgi.instance.area.default', using default path: " + configDirBase);
            }
            
            String compuwareSecurityConfigurationDirPath = configDirBase + File.separator + Activator.getBundleName();
            File compuwareSecurityConfigurationDir = new File(compuwareSecurityConfigurationDirPath);            
            if (!compuwareSecurityConfigurationDir.exists()) {
                logger.debug("Creating directory: " + compuwareSecurityConfigurationDir.getAbsolutePath());
                compuwareSecurityConfigurationDir.mkdirs();
            }
            logger.info("compuwareSecurityConfigurationDir: [" + compuwareSecurityConfigurationDir.getAbsolutePath() + "].");
            
            return compuwareSecurityConfigurationDir;
        //} catch (MalformedURLException mue) {
        } catch (Exception e) {
            throw new IllegalStateException("Could not determine Compuware Security Configuration Directory Location, osgiInstanceAreaToUse: [" 
                + osgiInstanceAreaToUse 
                + "], error: " + e.getMessage());
        }
    }
        
    /**
     * Ensures that the derived 'encryption method' property is dealt with.
     * 
     * @param properties
     * @param key
     * @return String
     */
    public static final String getLdapPropertyValue(Map<String, String> properties, String key) {
 
        // Encryption method is a derived field.
        String value = null;
        if (key.equalsIgnoreCase(ICompuwareSecurityLdapConfiguration.LDAP_ENCRYPTION_METHOD_KEY)) {
            String ldapUrl = properties.get(ICompuwareSecurityLdapConfiguration.LDAP_URL_KEY);
            if (ldapUrl.toLowerCase().startsWith("ldaps")) {
                value = ICompuwareSecurityLdapConfiguration.LDAP_ENCRYPTION_METHOD_SSL;
            } else {
                value = ICompuwareSecurityLdapConfiguration.LDAP_ENCRYPTION_METHOD_NONE;
            }
        } else {
            value = properties.get(key);
        }
                
        return value;
    }    
}