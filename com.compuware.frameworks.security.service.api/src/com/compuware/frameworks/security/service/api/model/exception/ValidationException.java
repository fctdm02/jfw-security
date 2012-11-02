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
public final class ValidationException extends Exception {

    /* */
	private static final long serialVersionUID = 1L;
	
	
	/* */
	private String invalidField;
	
	/* */
	private String reason;

	

    /** */
    public static final String FIELD_MULTI_TENANCY_REALM = "Multi Tenancy Realm"; 
    /** */
    public static final String FIELD_REALM_NAME = "Realm Name";
    /** */
    public static final String FIELD_ACTIVE_PASSWORD_POLICY_NAME = "Active Password Policy Name";
    /** */
    public static final String FIELD_PASSWORD_POLICY_NAME = "Password Policy Name";         
    /** */
    public static final String FIELD_USERNAME = "Username";
    /** */
    public static final String FIELD_DESCRIPTION = "Description";    
    /** */
    public static final String FIELD_GROUPNAME = "Groupname";
    /** */
    public static final String FIELD_ROLENAME = "Rolename";
    /** */
    public static final String FIELD_ROLE_DISPLAY_NAME = "Role Display Name";    
    /** */
    public static final String FIELD_PASSWORD = "Password";
    /** */
    public static final String FIELD_PASSWORD_VERIFY = "Password Verify";        
	/** */
	public static final String FIELD_FIRST_NAME = "First Name";
	/** */
    public static final String FIELD_LAST_NAME = "Last Name";
    /** */
    public static final String FIELD_EMAIL_ADDRESS = "Email Address";
	/** */
	public static final String FIELD_GROUP_NAME = "Group Name";
    /** */
    public static final String FIELD_HOST_NAME = "Host Name";
    /** */
    public static final String FIELD_PORT = "Port";
    /** */
    public static final String FIELD_DATABASE_NAME = "Database Name";
    /** */
    public static final String FIELD_DATABASE_TYPE = "Database Type";
    /** */
    public static final String FIELD_DATABASE_AUTHORIZATION_TYPE = "Database Authorization Type";
    /** */
    public static final String FIELD_ENCRYPTION_METHOD = "Encryption Method";
    /** */
    public static final String FIELD_ALL = "ALL";
    /** */
    public static final String FIELD_FIRST_RESULT = "First Result";
    /** */
    public static final String FIELD_MAX_RESULTS = "Max Results";
    /** */
    public static final String FIELD_EVENT_DETAILS = "Event Details";
    /** */
    public static final String FIELD_EVENT_DATE = "Event Date";
    /** */
    public static final String FIELD_IP_ADDRESS = "IP Address";
    /** */
    public static final String FIELD_PRINCIPAL_TYPE = "Principal Type";    
    /** */
    public static final String FIELD_PRINCIPAL_NAME = "Principal Name";
    /** */
    public static final String FIELD_NAME_VALUE_PAIRS = "Name Value Pairs";
    /** */
    public static final String FIELD_REASON = "Reason";
    /** */
    public static final String FIELD_SOURCE_REPOSITORY_NAME = "Source Repository Name";
    /** */
    public static final String FIELD_CREATION_DATE = "Creation Date";
    /** */
    public static final String FIELD_ENCODED_PASSWORD = "Encoded Password";
    /** */
    public static final String FIELD_OWNING_SECURITY_USER = "Owning Security User";
    /** */
    public static final String FIELD_MAX_SESSIONS_PER_USER = "Max Sessions Per User";
    /** */
    public static final String FIELD_MAX_INACTIVE_SESSION_TIMEOUT_MINUTES = "Max Inactive Session Timeout Minutes";
    /** */
    public static final String FIELD_MAX_SESSION_LIFE_MINUTES = "Max Session Life Minutes";
    /** */
    public static final String FIELD_SESSION_MONITOR_INTERVAL_MILLIS = "Session Monitor Interval Millis";

    
    /** */
    public static final String TOKEN_ZERO = "{0}";
    /** */
    public static final String TOKEN_ONE = "{1}";
    /** */
    public static final String REASON_CANNOT_BE_NULL = "Reason.0:cannot be null";    
    /** */
    public static final String REASON_CANNOT_BE_EMPTY = "Reason.1:cannot be empty";
    /** */
    public static final String REASON_MUST_BE_EMPTY = "Reason.2:must be empty";    
    /** */
    public static final String REASON_MUST_BE_POSITIVE_NONZERO_NUMBER = "Reason.3:must be a positive, non-zero, number";
    /** */
    public static final String REASON_CANNOT_BE_GREATER_THAN_256_CHARS = "Reason.4:cannot be greater than 256 characters.";
    /** */
    public static final String REASON_CANNOT_BE_GREATER_THAN__TOKEN__CHARS = "Reason.5:cannot be greater than [" + TOKEN_ZERO + "] characters.";
    /** */
    public static final String REASON_MINIMUM_LENGTH_NOT_SATISFIED = "Reason.6:must greater than [" + TOKEN_ZERO + "] characters.";    
    /** */
    public static final String REASON_CANNOT_BE_NEGATIVE = "Reason.7:cannot be negative";  
    /** */
    public static final String REASON_AT_LEAST_ONE_SEARCH_CRITERIA_MUST_BE_SPECIFIED = "Reason.8:At least one search criteria must be specified.";
    /** */
    public static final String REASON_MUST_BE_A_INTEGRAL_NUMBER = "Reason.9:must be an integral number";
    /** */
    public static final String REASON_MUST_BE_A_POSITIVE_INTEGRAL_NUMBER = "Reason.10:must be an positive integral number";      
    /** */
    public static final String REASON_MUST_BE_A_VALID_NUMBER = "Reason.11:must be a valid number";  
    /** */
    public static final String REASON_OPTIMISTIC_LOCK_FAILURE = "Reason.12:given version: [" + TOKEN_ZERO + "] does not match currently persisted version: [" + TOKEN_ONE + "]. Please Please re-read, and if needed, re-apply changes and retry save.";
    /** */
    public static final String REASON_MUST_BE_LESS_THAN = "Reason.13:[" + TOKEN_ZERO + "] must be less than [" + TOKEN_ONE + "]"; 
    /** */
    public static final String REASON_MUST_BE_BETWEEN = "Reason.14:[" + TOKEN_ZERO + "] must be between [" + TOKEN_ONE + "]"; 
    /** */
    public static final String REASON_INVALID_MIXTURE_OF_DATABASE_TYPE_FIELDS = "Reason.15:invalid mixture of database type DB values";
    /** */
    public static final String REASON_MISSING_KEY_VALUE_PAIRS = "Reason.16:missing configuration key/value pairs: [" + TOKEN_ZERO + "]";
    /** */
    public static final String REASON_INVALID_PREFIX = "Reason.17:[" + TOKEN_ZERO + "] is invalid and must be one of the following prefixes: [" + TOKEN_ONE + "]";
    /** */
    public static final String REASON_INVALID_ENUMERATED_VALUE = "Reason.18:[" + TOKEN_ZERO + "] is invalid and must be one of the following: [" + TOKEN_ONE + "]";
    /** */
    public static final String REASON_INVALID_STRING_LENGTH = "Reason.19:must be greater than: [" + TOKEN_ZERO + "] chars and less than: [" + TOKEN_ONE + "] chars"; 
    /** */
    public static final String REASON_INVALID_PARENTHESIZED_VALUE = "Reason.20:invalid parenthesized value, must start with '(' and end with ')'"; 
    /** */
    public static final String REASON_COULD_NOT_CONNECT_TO_LDAP = "Reason.21:could not connect to LDAP with given configuration";
    /** */
    public static final String REASON_COULD_NOT_AUTHENTICATE_TO_LDAP = "Reason.22:could not authenticate to LDAP with given configuration";
    /** */
    public static final String REASON_NO_LDAP_USERS_FOUND_WITH_GIVEN_BASE_AND_FILTER = "Reason.23:no LDAP users were found using search base: [" + TOKEN_ZERO + "] and search filter: [" + TOKEN_ONE + "]";    
    /** */
    public static final String REASON_NO_LDAP_GROUPS_FOUND_WITH_GIVEN_BASE_AND_FILTER = "Reason.24:no LDAP groups were found using search base: [" + TOKEN_ZERO + "] and search filter: [" + TOKEN_ONE + "]";    
    /** */
    public static final String REASON_COULD_NOT_CONNECT_TO_DATABAE = "Reason.25:could not connect to database with given configuration";
    /** */
    public static final String REASON_PASSWORD_VERIFY_DOES_NOT_MATCH_PASSWORD = "Reason.26:password verify does not match password";
    /** */
    public static final String REASON_NO_PASSWORD_SPECIFIED = "Reason.27:No password specified.";
    /** */
    public static final String REASON__TOKEN__DOES_NOT_MATCH__TOKEN__ = "Reason.28:[" + TOKEN_ZERO + "] does not match [" + TOKEN_ONE + "]";

    
    
    /**
     * This signature is to preserve backward compatibility.
     * 
     * @param message
     */
    public ValidationException(String message) {
        super(message);
    }
    
	/**
	 * 
	 * @param invalidField
	 * @param reason
	 */
    public ValidationException(String invalidField, String reason) {
    	super("");
    	this.invalidField = invalidField;
    	this.reason = reason;
    }
    
    /**
     * 
     * @param message
     * @param cause
     */
    public ValidationException(String invalidField, String reason, Throwable cause) {
        super("", cause);
        this.invalidField = invalidField;
        this.reason = reason;
    }    
        
    /**
     * 
     * @return
     */
    public String getInvalidField() {
        return this.invalidField;
    }
    
    /**
     * 
     * @return
     */
    public String getReason() {
        return this.reason;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Throwable#getMessage()
     */
    public String getMessage() {
        if (this.invalidField != null || this.reason != null) {
            return "Invalid Field: [" + this.invalidField + "] Reason: [" + this.reason + "]";    
        }
        return super.getMessage();
    }
}