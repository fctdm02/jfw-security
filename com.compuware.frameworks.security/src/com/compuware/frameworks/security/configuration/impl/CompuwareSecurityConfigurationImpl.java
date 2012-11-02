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
package com.compuware.frameworks.security.configuration.impl;

import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;

import org.apache.log4j.Logger;

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor;
import com.compuware.frameworks.security.configuration.persistence.file.CompuwareSecurityConfigurationFilePersistor;

/**
 * 
 * @author tmyers
 * 
 */
public final class CompuwareSecurityConfigurationImpl implements ICompuwareSecurityConfiguration {
	
	/* */
	private final Logger logger = Logger.getLogger(CompuwareSecurityConfigurationImpl.class);
	
	
	/* */
	private ICompuwareSecurityConfigurationPersistor compuwareSecurityConfigurationPersistor;

	
    /* */
    private Map<String, String> persistedJdbcConfiguration;

    /* */
    private Map<String, String> persistedLdapConfiguration;

    
	/* */
	private Map<String, String> compuwareSecurityJdbcConfiguration;

	/* */
	private Map<String, String> compuwareSecurityLdapConfiguration;
	
	
	/**
	 * Reads configuration from backing store and performs an initial validation of the properties.
	 * 
	 * Initializes using a default CompuwareSecurityConfigurationFilePersistor persistor
	 * 
	 * @throws IOException
	 */
	public CompuwareSecurityConfigurationImpl() throws IOException {
		this(new CompuwareSecurityConfigurationFilePersistor());
	}
	
	/**
	 * Reads configuration from backing store and performs an initial validation of the properties.
	 * 
	 * @param compuwareSecurityConfigurationPersistor
	 * @throws IOException
	 */
	public CompuwareSecurityConfigurationImpl(ICompuwareSecurityConfigurationPersistor compuwareSecurityConfigurationPersistor) throws IOException {
		setCompuwareSecurityConfigurationPersistor(compuwareSecurityConfigurationPersistor);
		initialize();				
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.configuration.ICompuwareSecurityConfiguration#initialize()
	 */
	public void initialize() throws IOException {
	    
	    logger.info("Reading Compuware Security configuration.");
	    
        this.compuwareSecurityJdbcConfiguration = this.compuwareSecurityConfigurationPersistor.readJdbcConfiguration();
        this.compuwareSecurityLdapConfiguration = this.compuwareSecurityConfigurationPersistor.readLdapConfiguration();
		
        this.persistedJdbcConfiguration = new TreeMap<String, String>();
        this.persistedLdapConfiguration = new TreeMap<String, String>();
		
        copyMaps();        
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#getCompuwareSecurityConfigurationPersistor()
	 */
	public ICompuwareSecurityConfigurationPersistor getCompuwareSecurityConfigurationPersistor() {
	    
	    return this.compuwareSecurityConfigurationPersistor;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#setCompuwareSecurityConfigurationPersistor(com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor)
	 */
    public void setCompuwareSecurityConfigurationPersistor(ICompuwareSecurityConfigurationPersistor compuwareSecurityConfigurationPersistor) {
    	
		if (compuwareSecurityConfigurationPersistor == null) {
			throw new IllegalStateException("compuwareSecurityConfigurationPersistor cannot be null.");
		}    	
    	this.compuwareSecurityConfigurationPersistor = compuwareSecurityConfigurationPersistor;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#writeConfiguration()
     */
    public void writeConfiguration() throws IOException {
        
    	logger.debug("Writing Compuware Security Configuration...");
    	this.compuwareSecurityConfigurationPersistor.writeJdbcConfiguration(this.compuwareSecurityJdbcConfiguration);
    	this.compuwareSecurityConfigurationPersistor.writeLdapConfiguration(this.compuwareSecurityLdapConfiguration);
    	
    	copyMaps();
    }

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#setJdbcConfiguration(java.util.Map)
	 */
	public void setJdbcConfiguration(Map<String, String> jdbcConfiguration) {
		this.compuwareSecurityJdbcConfiguration = jdbcConfiguration;		
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#setLdapConfiguration(java.util.Map)
	 */
	public void setLdapConfiguration(Map<String, String> ldapConfiguration) {
		this.compuwareSecurityLdapConfiguration = ldapConfiguration;
	}

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#getJdbcConfiguration()
     */
    public Map<String, String> getJdbcConfiguration() {
        Map<String, String> map = new TreeMap<String, String>();
        map.putAll(this.compuwareSecurityJdbcConfiguration); 
        return map;
    }

    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#getLdapConfiguration()
     */
    public Map<String, String> getLdapConfiguration() {
        Map<String, String> map = new TreeMap<String, String>();
        map.putAll(this.compuwareSecurityLdapConfiguration); 
        return map;
    }
    
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#getJdbcConfigurationFromPersistentStorage()
     */
    public Map<String, String> getJdbcConfigurationFromPersistentStorage() {
        return this.persistedJdbcConfiguration;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration#getLdapConfigurationFromPersistentStorage()
     */
    public Map<String, String> getLdapConfigurationFromPersistentStorage() {
        return this.persistedLdapConfiguration;
    }
    
    
    /*
     * 
     */
    private void copyMaps() {
        
        this.persistedJdbcConfiguration.putAll(this.compuwareSecurityJdbcConfiguration);
        this.persistedLdapConfiguration.putAll(this.compuwareSecurityLdapConfiguration);
    }
}