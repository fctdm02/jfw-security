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
package com.compuware.frameworks.security.configuration.persistence.file;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import org.apache.log4j.Logger;

import com.compuware.frameworks.security.AbstractConfiguration;
import com.compuware.frameworks.security.CompuwareSecurityConfigurationUtil;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityJdbcConfiguration;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityLdapConfiguration;
import com.compuware.frameworks.security.api.crypto.EncryptDecrypt;
import com.compuware.frameworks.security.crypto.CompuwareSecurityPrivateKey;

/**
 * 
 * @author tmyers
 * 
 */
public class CompuwareSecurityConfigurationFilePersistor implements ICompuwareSecurityConfigurationPersistor {

	/* */
	private final Logger logger = Logger.getLogger(CompuwareSecurityConfigurationFilePersistor.class);
		    		
	/* */
	protected static final String JDBC_CONFIG_FILE_PATH = "compuwareSecurityJdbcConfiguration.properties";
	
	/* */
	protected static final String LDAP_CONFIG_FILE_PATH = "compuwareSecurityLdapConfiguration.properties";
	
	
	/* */
	private File jdbcPropertiesFile;
	
	/* */
	private File ldapPropertiesFile;

	/* */
	private File configDir;

	/**
	 * @throws IOException
	 */
	public CompuwareSecurityConfigurationFilePersistor() throws IOException {
		this(JDBC_CONFIG_FILE_PATH, LDAP_CONFIG_FILE_PATH);
	}
	
	/**
	 * @param jdbcPropertiesFile
	 * @param ldapPropertiesFile
	 * @throws IOException
	 */
	public CompuwareSecurityConfigurationFilePersistor(
			String jdbcPropertiesFilePath, 
			String ldapPropertiesFilePath) throws IOException {

		configDir = CompuwareSecurityConfigurationUtil.getCompuwareSecurityConfigurationDir();			
		
		setJdbcConfigurationFile(jdbcPropertiesFilePath);
		setLdapConfigurationFile(ldapPropertiesFilePath);
		
		readJdbcConfiguration();
		readLdapConfiguration();
	}

	/**
	 * 
	 * @param jdbcFilePath
	 */
	public final void setJdbcConfigurationFile(String jdbcFilePath) {
		if (jdbcFilePath != null) {
			this.jdbcPropertiesFile = new File(configDir, jdbcFilePath);
		}
	}

	/**
	 * 
	 * @param ldapFilePath
	 */
	public final void setLdapConfigurationFile(String ldapFilePath) {
		if (ldapFilePath != null) {
			this.ldapPropertiesFile = new File(configDir, ldapFilePath);
		}
	}

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor#getDefaultJdbcConfiguration()
     */
    public final Map<String, String> getDefaultJdbcConfiguration() {
        Map<String, String> map = new TreeMap<String, String>();
        map.putAll(AbstractConfiguration.DEFAULT_JDBC_PROPERTIES);
        AbstractConfiguration.setSystemPropertyOverrides(map);
        return map;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor#readJdbcConfiguration()
     */
    public final Map<String, String> readJdbcConfiguration() throws IOException {
        
        Map<String, String> compuwareSecurityJdbcRepositoryConfiguration = null;
		if (this.jdbcPropertiesFile.exists()) {
		    compuwareSecurityJdbcRepositoryConfiguration = read(this.jdbcPropertiesFile);
		} else {
            logger.error("Could not read properties file: " + this.jdbcPropertiesFile.getAbsolutePath());
            compuwareSecurityJdbcRepositoryConfiguration = getDefaultJdbcConfiguration(); 
            this.write(compuwareSecurityJdbcRepositoryConfiguration, this.jdbcPropertiesFile);
		}
		
        // Ensure that a version exists, as it will be needed by the service layer in order to perform a save (for optimistic locking).
        if (compuwareSecurityJdbcRepositoryConfiguration.get(ICompuwareSecurityJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY) == null) {
            
            compuwareSecurityJdbcRepositoryConfiguration.put(
                    ICompuwareSecurityJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY, 
                    ICompuwareSecurityJdbcConfiguration.DEFAULT_JDBC_CONFIGURATION_VERSION_VALUE);
            
            logger.info("Added a default version for JDBC Configuration to be: " + compuwareSecurityJdbcRepositoryConfiguration.get(ICompuwareSecurityJdbcConfiguration.JDBC_CONFIGURATION_VERSION_KEY));
            this.write(compuwareSecurityJdbcRepositoryConfiguration, this.jdbcPropertiesFile);
        }
		
    	return compuwareSecurityJdbcRepositoryConfiguration;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor#writeJdbcConfiguration(java.util.Map)
     */
    public final void writeJdbcConfiguration(Map<String, String> jdbcConfiguration) throws IOException {
    	write(jdbcConfiguration, this.jdbcPropertiesFile);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor#getDefaultLdapConfiguration()
     */
    public final Map<String, String> getDefaultLdapConfiguration() {
        Map<String, String> map = new TreeMap<String, String>();
        map.putAll(AbstractConfiguration.DEFAULT_LDAP_PROPERTIES);
        AbstractConfiguration.setSystemPropertyOverrides(map);
        return map;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor#readLdapConfiguration()
     */
    public final Map<String, String> readLdapConfiguration() throws IOException {
        
        Map<String, String> compuwareSecurityLdapRepositoryConfiguration = null;
		if (this.ldapPropertiesFile.exists()) {
		    compuwareSecurityLdapRepositoryConfiguration = read(this.ldapPropertiesFile);
		} else {
            logger.error("Could not read properties file: " + this.ldapPropertiesFile.getAbsolutePath());
            compuwareSecurityLdapRepositoryConfiguration = getDefaultLdapConfiguration(); 
            this.write(compuwareSecurityLdapRepositoryConfiguration, this.ldapPropertiesFile);
		}		
		
		// Ensure that a version exists, as it will be needed by the service layer in order to perform a save (for optimistic locking).
		if (compuwareSecurityLdapRepositoryConfiguration.get(ICompuwareSecurityLdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY) == null) {
		    
		    compuwareSecurityLdapRepositoryConfiguration.put(
		            ICompuwareSecurityLdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY, 
		            ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_CONFIGURATION_VERSION_VALUE);
		    
		    logger.info("Added a default version for LDAP Configuration to be: " + compuwareSecurityLdapRepositoryConfiguration.get(ICompuwareSecurityLdapConfiguration.LDAP_CONFIGURATION_VERSION_KEY));
		    this.write(compuwareSecurityLdapRepositoryConfiguration, this.ldapPropertiesFile);
		}
		
		// If there are any missing key/value pairs add any defaults (where we can)
		String useTls = compuwareSecurityLdapRepositoryConfiguration.get(ICompuwareSecurityLdapConfiguration.LDAP_USE_TLS_KEY);
		if (useTls == null || useTls.trim().equals("")) {
		    logger.warn(ICompuwareSecurityLdapConfiguration.LDAP_USE_TLS_KEY + " property not found in LDAP Configuration, using default value of: " 
		        + ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_USE_TLS_VALUE);
		    
            compuwareSecurityLdapRepositoryConfiguration.put(
                ICompuwareSecurityLdapConfiguration.LDAP_USE_TLS_KEY, 
                ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_USE_TLS_VALUE);
		}

        // If there are any missing key/value pairs add any defaults (where we can)
        String performServerCertificateValidation = compuwareSecurityLdapRepositoryConfiguration.get(ICompuwareSecurityLdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY);
        if (performServerCertificateValidation == null || performServerCertificateValidation.trim().equals("")) {
            logger.warn(ICompuwareSecurityLdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY + " property not found in LDAP Configuration, using default value of: " 
                + ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_VALUE);
            
            compuwareSecurityLdapRepositoryConfiguration.put(
                ICompuwareSecurityLdapConfiguration.LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_KEY, 
                ICompuwareSecurityLdapConfiguration.DEFAULT_LDAP_PERFORM_SERVER_CERTIFICATE_VALIDATION_VALUE);
        }
		
    	return compuwareSecurityLdapRepositoryConfiguration;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor#writeLdapConfiguration(java.util.Map)
     */
    public final void writeLdapConfiguration(Map<String, String> ldapConfiguration) throws IOException {
    	write(ldapConfiguration, this.ldapPropertiesFile);
    }

    /*
     * 
     * @param file
     * @return
     * @throws IOException
     */
	private Map<String, String> read(File file) throws IOException {
	    
	    boolean needToWriteImmediately = false;
		
		Map<String, String> configurationPropertiesMap = new TreeMap<String, String>();
        Properties properties = new Properties();
        InputStream inputStream = null;
        
        try {
            inputStream = new FileInputStream(file);
            properties.load(inputStream);
            
            Iterator<Object> iterator = properties.keySet().iterator();
            while (iterator.hasNext()) {
            	String key = iterator.next().toString();
            	String value = properties.get(key).toString();
            	
                if ((key.equalsIgnoreCase(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY)) ) {
                    Object object = properties.get(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_CLEAR_TEXT_FLAG_KEY);
                    if (object == null || object.toString().equalsIgnoreCase("false")) {
                        value = EncryptDecrypt.decryptText(value, CompuwareSecurityPrivateKey.getInstance().getKey());
                    } else {
                        needToWriteImmediately = true;
                    }
                } else if (key.equalsIgnoreCase(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)) {
                    Object object = properties.get(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_CLEAR_TEXT_FLAG_KEY);
                    if (object == null || object.toString().equalsIgnoreCase("false")) {
                        value = EncryptDecrypt.decryptText(value, CompuwareSecurityPrivateKey.getInstance().getKey());
                    } else {
                        needToWriteImmediately = true;
                    }
                }
            	configurationPropertiesMap.put(key, value);
            }            
        } finally {
            
            properties.remove(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_CLEAR_TEXT_FLAG_KEY);
            properties.remove(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_CLEAR_TEXT_FLAG_KEY);

            configurationPropertiesMap.remove(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_CLEAR_TEXT_FLAG_KEY);
            configurationPropertiesMap.remove(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_CLEAR_TEXT_FLAG_KEY);
            
            if (inputStream != null) {
                inputStream.close();    
            }
        }

        // BZ-12984: http://dtw-bugzilla.nasa.cpwr.corp/bugzilla/show_bug.cgi?id=12984
        // If we just read unencrypted properties (i.e. the jdbc or ldap service account passwords and the 'passwordcleartext' property  was
        // present and set to 'false', then we need to perform an immediate write so that we can write the encrypted form of the password.
        if (needToWriteImmediately) {
            logger.info("Unencrypted service account passwords detected, performing an immediate write so that they are stored in encrypted form.");
            this.write(configurationPropertiesMap, file);
        }
		
		return configurationPropertiesMap;
	}

	/*
	 * 
	 * @param configurationPropertiesMap
	 * @param file
	 * @throws IOException
	 */
    private void write(Map<String, String> configurationPropertiesMap, File file) throws IOException {
    	
        logger.debug("Saving file: " + file.getAbsolutePath());
        BufferedOutputStream bos = null;
    	Properties properties = new Properties();
		Iterator<String> iterator = configurationPropertiesMap.keySet().iterator();
		
		while (iterator.hasNext()) {
			String key = iterator.next();
			String value = configurationPropertiesMap.get(key);
            if (key.equalsIgnoreCase(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY)
                || key.equalsIgnoreCase(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY)) {
                value = EncryptDecrypt.encryptText(value, CompuwareSecurityPrivateKey.getInstance().getKey());
            }               
			properties.put(key, value);
		}
    	
        try {
            bos = new BufferedOutputStream(new FileOutputStream(file));
            String comments = "Compuware Security Configuration";
            properties.store(bos, comments);
        } finally {
            if (bos != null) {
                bos.flush();
                bos.close();                    
            }
        }
    }
}