/*
* These materials contain confidential information and 
* trade secrets of Compuware Corporation. You shall 
* maintain the materials as confidential and shall not 
* disclose its contents to any third party except as may 
* be required by law or regulation. Use, disclosure, 
* or reproduction is prohibited without the prior express 
* written permission of Compuware Corporation.
* 
* All Compuware products listed within the materials are 
* trademarks of Compuware Corporation. All other company 
* or product names are trademarks of their respective owners.
* 
* Copyright (c) 2010 Compuware Corporation. All rights reserved.
* 
*/
package com.compuware.frameworks.security.persistence.dao;

/**
 * @author dresser
 * @author tmyers
 */
public interface IAclSql {
    
    /**
     * 
     * @return String
     */
    String getDeleteOldAuditEventSql();
	
	/**
	 * @return String
	 */
	String getExternalCredentialCreateSql();
	
	/**
	 * @return String 
	 */
	String getConfigurationCreateSql();
	
	/**
	 * 
	 * @return String
	 */
	String getInsertConfigurationSql();

	/**
	 * 
	 * @return String
	 */
	String getRetrieveConfigurationSql();
	
	/**
	 * 
	 * @return String
	 */
	String getIdentityClause();
	
	/**
	 * 
	 * @return String
	 */
	String getVarCharType();
	
	/**
	 * 
	 * @return String
	 */
	String getIntegerType(boolean bigInteger);
	
	/**
	 * 
	 * @return String
	 */
	String getAclEntryCreateSql();
	
	/**
	 * 
	 * @return String
	 */
	String getAclObjectIdentityCreateSql();
	
	/**
	 * 
	 * @return String
	 */
	String getAclSidCreateSql();
	    	
	/**
	 * 
	 * @return String
	 */
	String getAclClassCreateSql();
	
    /**
     * 
     * @return String
     */
    String getAclClassIdentityQuery();
    
    /**
     * 
     * @return String
     */
    String getAclSidIdentityQuery();

    /**
     * 
     * @return String
     */
    String getInsertAclClass();
    
    /**
     * 
     * @return String
     */
    String getInsertAclSid();
    
    /**
     * 
     * @return String
     */
    String getInsertAclObjectIdentity();
    
    /**
     * 
     * @return String
     */
    String getInsertAclEntry();
}