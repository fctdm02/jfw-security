/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product emails are trademarks of their respective owners.
 * 
 * Copyright 2011 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.authentication.exception;

/**
 * 
 * @author tmyers
 * 
 */
public class PasswordExpiredException extends Exception {
	
	/** */
	private static final long serialVersionUID = 1L;
	
	/**
	 * 
	 * @param message
	 */
	public PasswordExpiredException(String message) {
		super(message);
	}
}