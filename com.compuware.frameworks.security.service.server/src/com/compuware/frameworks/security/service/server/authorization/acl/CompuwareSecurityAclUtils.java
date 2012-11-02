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

import java.util.Iterator;
import java.util.List;

import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;

import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;
import com.compuware.frameworks.security.service.api.model.SecurityGroup;

/**
 * This class has the ability to apply ACLs against groups that the authenticated user belongs to.
 * 
 * @author tmyers
 *
 */
public final class CompuwareSecurityAclUtils {
	
    /*
     * 
     */
    private CompuwareSecurityAclUtils() {       
    }
    
	/**
	 * 
	 * @param objectIdentityRetrievalStrategy
	 * @param sidRetrievalStrategy
	 * @param managementService
	 * @param aclService
	 * @param requirePermission
	 * @param authentication
	 * @param domainObject
	 * @return
	 */
    public static boolean hasPermission(
    		ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy,
    		SidRetrievalStrategy sidRetrievalStrategy,
    		IManagementService managementService,
    		AclService aclService,
    		List<Permission> requirePermission,
    		Authentication authentication, 
    		Object domainObject) {
    	
        // Obtain the OID applicable to the domain object
        ObjectIdentity objectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity(domainObject);

        // Obtain the SIDs applicable to the principal
        List<Sid> sids = sidRetrievalStrategy.getSids(authentication);

        // Obtain the SIDs applicable to the groups that this authentication belongs to.
        if (!(authentication instanceof CompuwareSecurityAuthenticationToken)) {
        	throw new ServiceException("authentication must be an instance of CompuwareSecurityAuthenticationToken, yet is: " + authentication.getClass().getCanonicalName());
        }
        CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken = (CompuwareSecurityAuthenticationToken)authentication;
        addSidsForUserGroups(sids, compuwareSecurityAuthenticationToken, managementService);
                
        Acl acl = null;
        try {
            // Lookup only ACLs for SIDs we're interested in
            acl = aclService.readAclById(objectIdentity, sids);
            return acl.isGranted(requirePermission, sids, false);
        } catch (NotFoundException ignore) {
            return false;
        }
    }

    /**
     * 
     * @param sids
     * @param authentication
     * @param managementService
     */
    public static void addSidsForUserGroups(List<Sid> sids, CompuwareSecurityAuthenticationToken authentication, IManagementService managementService) {
    	
        // ********************************************************************
        // TDM: Begin
    	AbstractUser abstractUser = authentication.getUserObject();
    	try {
        	Iterator<SecurityGroup> iterator = managementService.getSecurityGroupsForUser(abstractUser, abstractUser.getMultiTenancyRealm()).iterator();
            while (iterator.hasNext()) {
            	String groupname = iterator.next().getGroupname();
            	Sid groupSid = new PrincipalSid(groupname);
            	sids.add(groupSid);
            }
    	} catch (ObjectNotFoundException onfe) {
    		throw new ServiceException("Could not find user with username: " + abstractUser.getUsername() + " in realm: " + abstractUser.getMultiTenancyRealm().getRealmName(), onfe);
    	}
        // TDM: End
        // ********************************************************************
    }
}
