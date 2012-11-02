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
package com.compuware.frameworks.security.api;

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration;

/**
 * 
 * @author tmyers
 * 
 */
public interface ICompuwareSecurity {
		
	/**
	 *  Provides a way to get/set persistable Compuware Security configuration.
	 *  <p>
	 *  There are three basic groupings of Compuware Security properties:
	 *  <ol>
	 *    <li> JDBC connection properties
	 *    <li> LDAP connection properties
	 *  </ol>
	 * 
	 * @return
	 */
	ICompuwareSecurityConfiguration getCompuwareSecurityConfiguration();
}