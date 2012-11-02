/**
 * Copyright (c) 1991-${year} Compuware Corporation. All rights reserved.
 * Unpublished - rights reserved under the Copyright Laws of the United States.
 *
 *
 * U.S. GOVERNMENT RIGHTS-Use, duplication, or disclosure by the U.S. Government is
 * subject to restrictions as set forth in Compuware Corporation license agreement
 * and as provided for in DFARS 227.7202-1(a) and 227.7202-3(a) (1995),
 * DFARS 252.227-7013(c)(1)(ii)(OCT 1988), FAR 12.212(a)(1995), FAR 52.227-19,
 * or FAR 52.227-14 (ALT III), as applicable. Compuware Corporation.
 */
package com.compuware.frameworks.security.service.server.authentication.jdbc;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;

import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityGroup;
import com.compuware.frameworks.security.service.api.model.SecurityRole;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;
import com.compuware.frameworks.security.service.server.ServiceProvider;

/**
 * 
 * Retrieve the entire set of granted authorities for a given user (SecurityUser, ShadowSecurityUser or SystemUser).
 * For the case of a ShadowSecurityUser (i.e. Customer LDAP authentication mode), a LDAP group list that the master LDAP 
 * user belongs to is also used to determine the total set of roles (i.e. a role may be associated to a LDAP group as well).
 * @author tmyers
 */
public final class JdbcAuthoritiesPopulator {

    /* */
    private IManagementService managementService;

    /**
     * 
     */
    public JdbcAuthoritiesPopulator() {
    }
    
    /**
     * 
     * @param managementService
     */
    public JdbcAuthoritiesPopulator(IManagementService managementService) {
        setManagementService(managementService);
    }
    
    /**
     * 
     * @param managementService
     */
    public void setManagementService(IManagementService managementService) {
        this.managementService = managementService;
    }

    /**
     * There are five ways in which a user is associated to granted authorities:
     * <ol>
     *   <li> Direct user-to-role association
     *   
     *   <li> Direct group-to-role association where the user is a member of the group and the 
     *   group is a "local" SecurityGroup
     *   
     *   <li> Direct group-to-role association where the user is a member of the group and the
     *   group is an "customer LDAP" group (i.e. ShadowSecurityGroup).  The list of LDAP groups that the
     *   user belongs to is specified by <code>userLdapGroups</code> and is assumed to be empty when the 
     *   authentication mode is "local" (indeed, this list will be ignored if this is the case)  
     *   
     *   <li> Indirect group-to-role association by virtue of the group hierarchy
     *   
     *   <li> Indirect user-to-role association by virtue of the role hierarchy
     * </ol>
     * 
     * @param abstractUser The user to obtain the associated granted authorities for
     * @param userLdapGroups When in "Customer LDAP" authentication mode, this refers to the collection of LDAP groups that the user
     * belongs to.  Any "ShadowSecurityGroups" that match and have associations with SecurityRoles will result in granted authorities.
     *  
     * @return A comprehensive (i.e. reachable) list of granted authorities for the user.  That is, indirect role associations by virtue
     * of group/role hierarchies are included as a convenience (and because it cannot be expected that the client application is aware of
     * the Spring Security "role hierarchy" construct.
     * 
     * @throws ObjectNotFoundException 
     */
    public Collection<GrantedAuthority> getGrantedAuthorities(AbstractUser abstractUser, Collection<String> userLdapGroups) throws ObjectNotFoundException {
        
    	Set<String> authorityNameSet = new TreeSet<String>();

        // ###
        // #1#
        // ###
        // See if there are any direct user-to-role mappings
    	MultiTenancyRealm multiTenancyRealm = abstractUser.getMultiTenancyRealm();
        Collection<SecurityRole> securityRolesForUser = this.managementService.getAllSecurityRolesForUser(
        	abstractUser.getUsername(), 
        	multiTenancyRealm);
        
        Iterator<SecurityRole> securityRolesForUserIterator = securityRolesForUser.iterator();
        while (securityRolesForUserIterator.hasNext()) {
            
        	SecurityRole securityRole = securityRolesForUserIterator.next();
        	authorityNameSet.add(securityRole.getRoleName());
        }
        
        
        // For all groups that the user is a member of, see if there are any group-to-role mappings (direct or indirect)
        Collection<SecurityGroup> securityGroupsForUser = this.managementService.getSecurityGroupsForUser(
        	abstractUser, 
        	multiTenancyRealm);
        
        Iterator<SecurityGroup> securityGroupsForUserIterator = securityGroupsForUser.iterator();
        while (securityGroupsForUserIterator.hasNext()) {
        	
        	SecurityGroup securityGroup = securityGroupsForUserIterator.next();

            // ###
            // #2#
            // ###
        	// See if there are any direct group-to-role mappings for this group.
            Collection<SecurityRole> securityRolesForSecurityGroup = this.managementService.getAllSecurityRolesForGroup(
            	securityGroup.getGroupname(), 
            	multiTenancyRealm);
            
            Iterator<SecurityRole> securityRolesForSecurityGroupIterator = securityRolesForSecurityGroup.iterator();
            while (securityRolesForSecurityGroupIterator.hasNext()) {
                
            	SecurityRole securityRole = securityRolesForSecurityGroupIterator.next();
            	authorityNameSet.add(securityRole.getRoleName());
            }
                        
            // ###
            // #4#
            // ###            
            // See if there are any indirect group-to-role mappings for this group by traversing up the group hierarchy (recursively).
            SecurityGroup ancestralSecurityGroup = securityGroup.getParentGroup();
            while (ancestralSecurityGroup != null) {
            	
                Collection<SecurityRole> securityRolesForAncestralSecurityGroup = this.managementService.getAllSecurityRolesForGroup(
                	ancestralSecurityGroup.getGroupname(), 
                	multiTenancyRealm);
                
                Iterator<SecurityRole> securityRolesForAncestralSecurityGroupIterator = securityRolesForAncestralSecurityGroup.iterator();
                while (securityRolesForAncestralSecurityGroupIterator.hasNext()) {
                    
                	SecurityRole securityRole = securityRolesForAncestralSecurityGroupIterator.next();
                	authorityNameSet.add(securityRole.getRoleName());
                }
                
                ancestralSecurityGroup = ancestralSecurityGroup.getParentGroup();
            }
        }

        
        // If we are dealing with a shadow security user, then see if the given list of LDAP groups (presumed to correspond
        // to the actual LDAP user represented by the given shadow security user) have any shadow security groups associated 
        // any with security roles.
        if (userLdapGroups != null && userLdapGroups.size() > 0) {
        	
        	Iterator<String> userLdapGroupIterator = userLdapGroups.iterator();
        	while (userLdapGroupIterator.hasNext()) {
        		
        		String ldapGroupname = userLdapGroupIterator.next();
        		
        		ShadowSecurityGroup shadowSecurityGroup = this.managementService.getShadowSecurityGroupByGroupname(
        			ldapGroupname, 
        			multiTenancyRealm);
        		
                // ###
                // #3#
                // ###        		
        		if (shadowSecurityGroup != null) {
        		    
                	Collection<SecurityRole> securityRolesForShadowSecurityGroup = this.managementService.getAllSecurityRolesForSecurityPrincipal(
            			shadowSecurityGroup.getGroupname(), 
                		multiTenancyRealm);
                	
                	Iterator<SecurityRole> securityRolesForShadowSecurityGroupIterator = securityRolesForShadowSecurityGroup.iterator();
                    while (securityRolesForShadowSecurityGroupIterator.hasNext()) {
                        
                    	SecurityRole securityRole = securityRolesForShadowSecurityGroupIterator.next();
                    	authorityNameSet.add(securityRole.getRoleName());
                    }
        		}
        	}
        }
        
        
        // ###
        // #5#
        // ###        
    	// Ensure that we get all reachable authorities (i.e. indirect by virtue of the role hierarchy) 
        // This is in case the client does their own version of view layer security.
		Collection<GrantedAuthority> reachableAuthorities = null;
		if (!authorityNameSet.isEmpty()) {
			
	        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
	        Iterator<String> authorityNameSetIterator = authorityNameSet.iterator();
	        while (authorityNameSetIterator.hasNext()) {
	        	String authorityName = authorityNameSetIterator.next();
	        	authorities.add(new GrantedAuthorityImpl(authorityName));
	        }
			
			reachableAuthorities = ServiceProvider.getInstance().getRoleHierarchyImpl().getReachableGrantedAuthorities(authorities);
    		if (reachableAuthorities != null && !reachableAuthorities.isEmpty()) {
    			Iterator<GrantedAuthority> reachableAuthoritiesIterator = reachableAuthorities.iterator();
    			while (reachableAuthoritiesIterator.hasNext()) {
    				GrantedAuthority reachableAuthority = reachableAuthoritiesIterator.next();
    				authorityNameSet.add(reachableAuthority.getAuthority());
    			}
    		}
		}
    	
        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        Iterator<String> authorityNameSetIterator = authorityNameSet.iterator();
        while (authorityNameSetIterator.hasNext()) {
        	String authorityName = authorityNameSetIterator.next();
        	authorities.add(new GrantedAuthorityImpl(authorityName));
        }
    			
    	return authorities;	
    }
}