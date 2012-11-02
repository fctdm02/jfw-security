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

import org.springframework.security.acls.afterinvocation.AclEntryAfterInvocationCollectionFilteringProvider;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;

import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;

/**
 * This class has the ability to apply ACLs against groups that the authenticated user belongs to.
 * 
 * @author tmyers
 *
 */
public final class CompuwareSecurityAclEntryAfterInvocationCollectionFilteringProvider extends AclEntryAfterInvocationCollectionFilteringProvider {

	/* */
	private IManagementService managementService;

	/**
	 * 
	 * @param aclService
	 * @param requirePermission
	 * @param managementService
	 */
    public CompuwareSecurityAclEntryAfterInvocationCollectionFilteringProvider(
    		AclService aclService, 
    		List<Permission> requirePermission,
    		IManagementService managementService) {
    	super(aclService, requirePermission);
    	this.managementService = managementService;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.acls.afterinvocation.AbstractAclProvider#hasPermission(org.springframework.security.core.Authentication, java.lang.Object)
     */
    protected boolean hasPermission(Authentication authentication, Object domainObject) {
    	
        if (!(authentication instanceof CompuwareSecurityAuthenticationToken)) {
        	throw new ServiceException("authentication must be an instance of CompuwareSecurityAuthenticationToken, yet is: " + authentication.getClass().getCanonicalName());
        }
        CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken = (CompuwareSecurityAuthenticationToken)authentication;
    	
        return CompuwareSecurityAclUtils.hasPermission(
        		objectIdentityRetrievalStrategy,
        		sidRetrievalStrategy,
        		managementService,
        		aclService,
        		requirePermission,
        		compuwareSecurityAuthenticationToken, 
        		domainObject);
    }
}