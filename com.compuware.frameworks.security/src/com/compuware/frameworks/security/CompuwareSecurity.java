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

import java.io.IOException;

import org.apache.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.support.AbstractApplicationContext;

import com.compuware.frameworks.security.api.ICompuwareSecurity;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfigurationPersistor;
import com.compuware.frameworks.security.configuration.impl.CompuwareSecurityConfigurationImpl;
import com.compuware.frameworks.security.configuration.persistence.file.CompuwareSecurityConfigurationFilePersistor;

/**
 * Bootstrap bean class for JFW-Security "core" bundle.  This is used for clients that want to access services via the 
 * singleton instance here, that is accessible outside of Spring via the <code>CompuwareSecurity.getInstance()</code>                                                     
 * call. It is preferred, however, that clients use the Spring/OSGi approach            
 * (i.e. import the Spring beans as OSGi "services" that are exported here:<br>
 * <ul>             
 *   <li><b>OSGi Service ID</b> (Interface)
 *   <li>-----------------------------------------------
 *   <li><b>compuwareSecurityConfiguration</b> (com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration)
 * </ul>                                                                                    
 * @author tmyers
 * 
 */
public class CompuwareSecurity implements ICompuwareSecurity, ApplicationContextAware {

	/* */
	private final Logger logger = Logger.getLogger(CompuwareSecurity.class);
	
	/*  */
	private static AbstractApplicationContext applicationContext;

	/**
	 * 
	 */
	public CompuwareSecurity() {
		
	}
		
	/**
	 * 
	 * @return
	 */
	public static ICompuwareSecurity getInstance() {
		return (ICompuwareSecurity)applicationContext.getBean("compuwareSecurity");
	}

	/**
	 * @param applicationContextParameter
	 * 
	 * @throws BeansException
	 */
	public synchronized final void setApplicationContext(ApplicationContext applicationContextParameter) throws BeansException {
		
		logger.info("CompuwareSecurity: initializing..." + applicationContextParameter);
		applicationContext = (AbstractApplicationContext)applicationContextParameter;
  	}
				
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.api.ICompuwareSecurity#getCompuwareSecurityConfiguration()
	 */
	public ICompuwareSecurityConfiguration getCompuwareSecurityConfiguration() {		
		return (ICompuwareSecurityConfiguration)applicationContext.getBean("compuwareSecurityConfiguration");		
	}

		
	// These methods don't belong in an exposed class (they are certainly not in the main ICompuwareSecurity interface), but they need
	// to be here because the unit tests for the configuration code rely upon these to exercise the code.
	/**
	 * 
	 * @return
	 */
	public ICompuwareSecurityConfigurationPersistor createCompuwareSecurityConfigurationFilePersistor() throws IOException {
		return new CompuwareSecurityConfigurationFilePersistor();
	}

	/**
	 * @param jdbcPropertiesFilename
	 * @param ldapPropertiesFilename
	 * @throws IOException
	 */
	public ICompuwareSecurityConfigurationPersistor createCompuwareSecurityConfigurationFilePersistor(
			String jdbcPropertiesFilename, 
			String ldapPropertiesFilename) throws IOException {
		
		return new CompuwareSecurityConfigurationFilePersistor(
				jdbcPropertiesFilename,
				ldapPropertiesFilename);
	}
	
	/**
	 * @param compuwareSecurityConfigurationPersistor
	 * @return
	 * @throws IOException
	 */
	public ICompuwareSecurityConfiguration createCompuwareSecurityConfiguration(
			ICompuwareSecurityConfigurationPersistor compuwareSecurityConfigurationPersistor) throws IOException {
		return new CompuwareSecurityConfigurationImpl(compuwareSecurityConfigurationPersistor);
	}

	/**
	 * @return
	 * @throws IOException
	 */
	public ICompuwareSecurityConfiguration createCompuwareSecurityConfiguration() throws IOException {
		return new CompuwareSecurityConfigurationImpl();
	}
}