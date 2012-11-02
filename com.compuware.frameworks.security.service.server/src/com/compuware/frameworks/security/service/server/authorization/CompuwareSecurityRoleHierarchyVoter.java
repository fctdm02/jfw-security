/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2012 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.server.authorization;

import java.util.Collection;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Extended to resolve NullPointerException thrown in RoleVoter when the 
 * authorities collection is empty. (i.e. changed how this collection is iterated)
 * 
 * @author tmyers
 */
public final class CompuwareSecurityRoleHierarchyVoter extends RoleVoter {
    
    /* */
    private RoleHierarchy roleHierarchy;

    /**
     * 
     * @param roleHierarchy
     */
    public CompuwareSecurityRoleHierarchyVoter(RoleHierarchy roleHierarchy) {
        Assert.notNull(roleHierarchy, "RoleHierarchy must not be null");
        this.roleHierarchy = roleHierarchy;
    }
    
    /**
     * @param authentication
     * @param object
     * @param attributes
     * @return 
     */
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        
        int result = ACCESS_ABSTAIN;
        Collection<GrantedAuthority> authorities = roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
        
        for (ConfigAttribute attribute : attributes) {
            if (this.supports(attribute)) {
                result = ACCESS_DENIED;

                // Attempt to find a matching granted authority
                if (authorities != null && authorities.size() > 0) {
                    for (GrantedAuthority authority : authorities) {
                        if (attribute.getAttribute().equals(authority.getAuthority())) {
                            return ACCESS_GRANTED;
                        }
                    }
                }
            }
        }

        return result;
    }
}