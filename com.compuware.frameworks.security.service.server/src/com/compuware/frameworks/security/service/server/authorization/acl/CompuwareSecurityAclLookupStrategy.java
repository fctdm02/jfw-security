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
package com.compuware.frameworks.security.service.server.authorization.acl;

import java.util.List;
import java.util.Map;

import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

import com.compuware.frameworks.security.persistence.dao.jdbc.ISecurityDataSourceWrapper;

/**
 * This class has the ability to apply ACLs against groups that the authenticated user belongs to.
 * 
 * @author tmyers
 *
 */
public final class CompuwareSecurityAclLookupStrategy implements LookupStrategy {
    
    /* */
    private BasicLookupStrategy lookupStrategy;

    /* */
    private ISecurityDataSourceWrapper securityDataSourceWrapper;
    
    /* */
    private AclCache aclCache;
    
    /* */
    private AclAuthorizationStrategy aclAuthorizationStrategy;
    
    /* */
    private AuditLogger aclAuditLogger;
    
    /**
     * 
     * @param securityDataSourceWrapper
     * @param aclCache
     * @param aclAuthorizationStrategy
     * @param aclAuditLogger
     */
    public CompuwareSecurityAclLookupStrategy(
            ISecurityDataSourceWrapper securityDataSourceWrapper, 
            AclCache aclCache,
            AclAuthorizationStrategy aclAuthorizationStrategy, 
            AuditLogger aclAuditLogger) {

        this.securityDataSourceWrapper = securityDataSourceWrapper;
        this.aclCache = aclCache;
        this.aclAuthorizationStrategy = aclAuthorizationStrategy;
        this.aclAuditLogger = aclAuditLogger;
        
        setDataSource(this.securityDataSourceWrapper);
    }    
        
    /**
     * 
     * @param securityDataSourceWrapper
     */
    public void setDataSource(ISecurityDataSourceWrapper securityDataSourceWrapper) {
        
        this.securityDataSourceWrapper = securityDataSourceWrapper;
        
        lookupStrategy = new BasicLookupStrategy(
                this.securityDataSourceWrapper.getDataSource(), 
                this.aclCache, 
                this.aclAuthorizationStrategy, 
                this.aclAuditLogger);
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.acls.jdbc.LookupStrategy#readAclsById(java.util.List, java.util.List)
     */
    public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) {
        return lookupStrategy.readAclsById(objects, sids);
    }    
}