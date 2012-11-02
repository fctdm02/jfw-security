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
package com.compuware.frameworks.security.service.api.authentication;


/**
 * 
 * 
 * @author tmyers
 * 
 */
public interface IAuthenticationCredentialCollector {
	
	/**
	 * 
	 * @return username
	 */
	String getUsername();
	
	/**
	 * 
	 * @return password
	 */
	String getPassword();
}