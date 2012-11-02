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
package com.compuware.frameworks.security.persistence;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.ResourceTransactionManager;

import com.compuware.frameworks.security.persistence.dao.IAclSql;
import com.compuware.frameworks.security.persistence.dao.IAuditEventDao;
import com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao;
import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao;
import com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao;
import com.compuware.frameworks.security.persistence.dao.jdbc.ISecurityDataSourceWrapper;
import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;

/**
 * 
 * @author tmyers
 * 
 */
public interface IPersistenceProvider {

	/**
	 * 
	 * @return
	 */
	IAuditEventDao getAuditEventDao();

	/**
	 * 
	 * @return
	 */
	IMigrationRecordDao getMigrationRecordDao();
	
	/**
	 * 
	 * @return
	 */
	IMultiTenancyRealmDao getMultiTenancyRealmDao();
	
	/**
	 * 
	 * @return
	 */
	ISecurityPrincipalDao getSecurityPrincipalDao();
	
	/**
	 * 
	 * @return
	 */
	ISecurityRoleDao getSecurityRoleDao();
	
	/**
	 * Used for raw JDBC access to tables not explicitly controlled by the Hibernate 
	 * persistence layer (i.e. those tables not related to the domain model, such as
	 *  for ACLs and the Configuration table. 
	 * 
	 * @return
	 */
	JdbcTemplate getJdbcTemplate(); 

	/**
	 * Intended to be used to get the Hibernate config so that SchemaExport can be invoked in order
	 * to create the DB schema.
	 *  
	 * @return
	 */
	ISecurityDataSourceWrapper getSecurityDataSourceWrapper();

	/**
	 * 
	 * @return
O	 */
	IAclSql getAclSql();

	/**
	 * Intended to be used to get the Hibernate config so that SchemaExport can be invoked in order
	 * to create the DB schema.
	 *  
	 * @return
	 */
	ResourceTransactionManager getHibernateTransactionManager();
	
	/**
	 * 
	 * @return
	 */
	String getSchemaVersion();
	
	/**
	 * 
	 * @return
	 */
	String getBundleVersion();
	
    /**
     * Causes the Spring context to be reloaded (i.e. refreshed) using any new configuration values 
     * (if they have been changed) 
     */
    void refresh();
    
    /**
     * @return <code>true</code> if the Spring context is currently being refreshed; 
     * <code>false</code> otherwise.
     */
    boolean isRefreshing();
    
    /**
     * 
     * @param driverClassName
     * @param connectionString
     * @param serviceAccountUsername
     * @param serviceAccountPassword
     * @throws InvalidCredentialsException
     * @throws InvalidConnectionException
     */
    void testJdbcConnection(
        String driverClassName,
        String connectionString,
        String serviceAccountUsername,
        String serviceAccountPassword) 
    throws 
        InvalidCredentialsException, 
        InvalidConnectionException;    
}