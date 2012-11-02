/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product emails are trademarks of their respective owners.
 * 
 * Copyright 2010 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.model.exception;

/**
 * 
 * @author tmyers
 * 
 */
public final class PasswordPolicyException extends Exception {
	
	/** */
	private static final long serialVersionUID = 1L;
	

	/** */
	public static final String PASSWORD_IS_NULL = "PASSWORD_IS_NULL"; 

    /** */
    public static final String PASSWORD_IS_EMPTY = "PASSWORD_IS_EMPTY"; 
	
    /** */
    public static final String PASSWORD_VERIFY_IS_NULL = "PASSWORD_VERIFY_IS_NULL"; 
	
	/** */
	public static final String PASSWORD_VERIFY_IS_INCORRECT = "PASSWORD_VERIFY_IS_INCORRECT"; 

	/** */
	public static final String GIVEN_CURRENT_PASSWORD_IS_INCORRECT = "GIVEN_CURRENT_PASSWORD_IS_INCORRECT"; 
	
	/** */
	public static final String MIN_PASSWORD_LENGTH_NOT_MET = "MIN_PASSWORD_LENGTH_NOT_MET"; 

    /** */
    public static final String MAX_PASSWORD_LENGTH_EXCEEDED = "MAX_PASSWORD_LENGTH_EXCEEDED"; 
	
	/** */
	public static final String MIN_NUMBER_SPECIAL_CHARS_NOT_MET = "MIN_NUMBER_SPECIAL_CHARS_NOT_MET"; 

	/** */
	public static final String MIN_NUMBER_CHARS_NOT_MET = "MIN_NUMBER_CHARS_NOT_MET";
	
	/** */
	public static final String MIN_NUMBER_DIGITS_NOT_MET = "MIN_NUMBER_DIGITS_NOT_MET";

	/** */
	public static final String PASSWORD_HISTORY_NOT_MET = "PASSWORD_HISTORY_NOT_MET";
	
	/** */
	private String policyViolation;

	/**
	 * @param policyViolation
	 */
	public PasswordPolicyException(String policyViolation) {		
		super("");
		this.policyViolation = policyViolation;
	}
	
	/**
	 * @param message
	 * @param policyViolation
	 */
	public PasswordPolicyException(String message, String policyViolation) {		
		super(message);
		this.policyViolation = policyViolation;
	}
	
	/**
	 * 
	 * @return policyViolation
	 */
	public String getPolicyViolation() {
		return this.policyViolation;
	}
	
	/*
	 * (non-Javadoc)
	 * @see java.lang.Throwable#getMessage()
	 */
	public String getMessage() {
		return super.getMessage() + ", policyViolation: " + this.policyViolation;
	}	
}