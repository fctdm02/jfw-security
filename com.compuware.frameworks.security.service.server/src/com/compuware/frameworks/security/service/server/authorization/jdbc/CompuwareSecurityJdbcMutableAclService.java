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
package com.compuware.frameworks.security.service.server.authorization.jdbc;

import java.util.List;

import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.Sid;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

import com.compuware.frameworks.security.persistence.dao.IAclSql;
import com.compuware.frameworks.security.persistence.dao.jdbc.ISecurityDataSourceWrapper;
import com.compuware.frameworks.security.service.api.exception.ServiceException;

/**
 * 
 * @author tmyers
 */
public final class CompuwareSecurityJdbcMutableAclService extends JdbcMutableAclService {

	/* */
	private final Logger logger = Logger.getLogger(CompuwareSecurityJdbcMutableAclService.class);
			
    /* */
    private IAclSql aclSql;

    /**
     * 
     * @param securityDataSourceWrapper
     * @param aclSql
     * @param lookupStrategy
     * @param aclCache
     */
    public CompuwareSecurityJdbcMutableAclService(
            ISecurityDataSourceWrapper securityDataSourceWrapper, 
    		IAclSql aclSql,
    		LookupStrategy lookupStrategy, 
    		AclCache aclCache) {
        super(securityDataSourceWrapper.getDataSource(), lookupStrategy, aclCache);        
        logger.debug("CompuwareSecurityJdbcMutableAclService initalizing ACL service.");
        setDataSource(securityDataSourceWrapper);
        setAclSql(aclSql);        
        setClassIdentityQuery(this.aclSql.getAclClassIdentityQuery());
        setSidIdentityQuery(this.aclSql.getAclSidIdentityQuery());
        setInsertObjectIdentitySql(this.aclSql.getInsertAclObjectIdentity());
        setInsertClassSql(this.aclSql.getInsertAclClass());
        setInsertEntrySql(this.aclSql.getInsertAclEntry());
        setInsertSidSql(this.aclSql.getInsertAclSid());
    }
    
    /**
     * 
     * @param securityDataSourceWrapper
     */
    public void setDataSource(ISecurityDataSourceWrapper securityDataSourceWrapper) {
        super.jdbcTemplate.setDataSource(securityDataSourceWrapper.getDataSource());
    }
    
    /**
     * 
     * @param aclSql
     */
    public void setAclSql(IAclSql aclSql) {
        this.aclSql = aclSql;
    }
    
    /**
     * 
     * @return
     */
    public DataSource getDataSource() {
    	return super.jdbcTemplate.getDataSource();
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.acls.jdbc.JdbcMutableAclService#createOrRetrieveSidPrimaryKey(org.springframework.security.acls.model.Sid, boolean)
     */
    protected Long createOrRetrieveSidPrimaryKey(Sid sid, boolean allowCreate) {
        Assert.notNull(sid, "Sid required");

        String sidName = null;
        boolean sidIsPrincipal = true;

        if (sid instanceof PrincipalSid) {
            sidName = ((PrincipalSid) sid).getPrincipal();
        } else if (sid instanceof GrantedAuthoritySid) {
            sidName = ((GrantedAuthoritySid) sid).getGrantedAuthority();
            sidIsPrincipal = false;
        } else {
            throw new IllegalArgumentException("Unsupported implementation of Sid");
        }

        List<Long> sidIds = jdbcTemplate.queryForList(
                this.aclSql.getAclSidIdentityQuery(), 
                new Object[] {Boolean.valueOf(sidIsPrincipal), sidName},  
                Long.class);

        if (!sidIds.isEmpty()) {
            return sidIds.get(0);
        }

        if (allowCreate) {
            jdbcTemplate.update(
                    this.aclSql.getInsertAclSid(), 
                    new Object[] {Boolean.valueOf(sidIsPrincipal), 
                        sidName});
            
            Assert.isTrue(TransactionSynchronizationManager.isSynchronizationActive(), "Transaction must be running");
            
            sidIds = jdbcTemplate.queryForList(
                    this.aclSql.getAclSidIdentityQuery(), 
                    new Object[] {Boolean.valueOf(sidIsPrincipal), sidName},  
                    Long.class);

            if (!sidIds.isEmpty()) {
                return sidIds.get(0);
            }
            
            throw new ServiceException("Could not retrieve primary key for ACL SID just created for SID: " + sidName);
        }

        return null;
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.acls.jdbc.JdbcMutableAclService#createOrRetrieveClassPrimaryKey(java.lang.String, boolean)
     */
    protected Long createOrRetrieveClassPrimaryKey(String type, boolean allowCreate) {
        List<Long> classIds = jdbcTemplate.queryForList(this.aclSql.getAclClassIdentityQuery(), new Object[] {type}, Long.class);

        if (!classIds.isEmpty()) {
            return classIds.get(0);
        }

        if (allowCreate) {
            jdbcTemplate.update(this.aclSql.getInsertAclClass(), type);
            Assert.isTrue(TransactionSynchronizationManager.isSynchronizationActive(),
                    "Transaction must be running");
            
            classIds = jdbcTemplate.queryForList(this.aclSql.getAclClassIdentityQuery(), new Object[] {type}, Long.class);

            if (!classIds.isEmpty()) {
                return classIds.get(0);
            }
            
            throw new ServiceException("Could not retrieve primary key for ACL Class just created for Class: " + type);
        }

        return null;
    }
 }