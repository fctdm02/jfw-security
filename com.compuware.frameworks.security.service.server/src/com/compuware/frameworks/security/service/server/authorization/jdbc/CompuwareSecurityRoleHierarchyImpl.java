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

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.core.GrantedAuthority;

import com.compuware.frameworks.security.persistence.dao.jdbc.ISecurityDataSourceWrapper;
import com.compuware.frameworks.security.service.api.management.IManagementService;


/**
 * 
 * This Role Hierarchy implementation reads the role hierarchy from the database, rather than rely upon
 * a static configuration in the Spring application context file.
 * 
 * @author tmyers
 */
public final class CompuwareSecurityRoleHierarchyImpl extends RoleHierarchyImpl {

    /* */
    private final Logger logger = Logger.getLogger(CompuwareSecurityRoleHierarchyImpl.class);
    
    /* */
    private JdbcTemplate jdbcTemplate;
    
    /* */
    private String roleHierarchyStringRepresentation;
    
    /**
     * @param securityDataSourceWrapper
     */
    public CompuwareSecurityRoleHierarchyImpl(ISecurityDataSourceWrapper securityDataSourceWrapper) {
        setDataSource(securityDataSourceWrapper);
    }
    
    /**
     * @param securityDataSourceWrapper
     */
    public void setDataSource(ISecurityDataSourceWrapper securityDataSourceWrapper) {
        this.jdbcTemplate = new JdbcTemplate(securityDataSourceWrapper.getDataSource());
        loadHierarchy();
    }
        
    /** 
     * Loads the role hierarchy from the DB.
     * <p>
     * From: http://static.springsource.org/spring-security/site/docs/3.1.x/reference/authz-arch.html
     * 
     * It is a common requirement that a particular role in an application should automatically "include" other roles. 
     * For example, in an application which has the concept of an "admin" and a "user" role, you may want an admin to 
     * be able to do everything a normal user can. To achieve this, you can either make sure that all admin users are 
     * also assigned the "user" role. Alternatively, you can modify every access constraint which requires the "user" 
     * role to also include the "admin" role. This can get quite complicated if you have a lot of different roles in 
     * your application.
     * 
     * The use of a role-hierarchy allows you to configure which roles (or authorities) should include others. An extended
     * version of Spring Security's RoleVoter, RoleHierarchyVoter, is configured with a RoleHierarchy, from which it obtains
     * all the "reachable authorities" which the user is assigned. A typical configuration might look like this:
     *
     * <pre>
       <bean id="roleHierarchy" class="org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl">
          <property name="hierarchy">
             ROLE_ADMIN > ROLE_STAFF
             ROLE_STAFF > ROLE_USER
             ROLE_USER > ROLE_GUEST
          </property>
       </bean>     
       <bean id="roleVoter" class="org.springframework.security.access.vote.RoleHierarchyVoter">
          <constructor-arg ref="roleHierarchy" />      
       </pre>
     *
     * Here we have four roles in a hierarchy ROLE_ADMIN => ROLE_STAFF => ROLE_USER => ROLE_GUEST. A user who is 
     * authenticated with ROLE_ADMIN, will behave as if they have all four roles when security constraints are evaluated 
     * against an AccessDecisionManager configured with the above RoleHierarchyVoter. The > symbol can be thought of as 
     * meaning "includes".
     * 
     * Role hierarchies offer a convenient means of simplifying the access-control configuration data for your application 
     * and/or reducing the number of authorities which you need to assign to a user. For more complex requirements you may 
     * wish to define a logical mapping between the specific access-rights your application requires and the roles that are 
     * assigned to users, translating between the two when loading the user information.
     */
    synchronized public void loadHierarchy() {
        
        logger.debug("Loading role hierarchy from the database");
        StringBuilder sb = new StringBuilder();
                
        // First, build the map that relates the id to the role name
        Map<Number, String> roleMap = new HashMap<Number, String>();
        List<?> list = this.jdbcTemplate.queryForList("SELECT SECURITY_ROLE_ID, ROLE_NAME FROM SECURITY_ROLE");
        Iterator<?> iterator = list.iterator();
        while (iterator.hasNext()) {
            
            Map<?,?> listMap = (Map<?,?>)iterator.next();
            Number securityRoleId = (Number)listMap.get("SECURITY_ROLE_ID");
            String roleName = (String)listMap.get("ROLE_NAME");
            roleMap.put(securityRoleId, roleName);
        }
        
        // Next, iterate through the results again, this time looking at the parent security role id so that we can build the hierarchy.
        list = this.jdbcTemplate.queryForList("SELECT SECURITY_ROLE_ID, INCLUDED_SECURITY_ROLE_ID FROM SECURITY_ROLE_HIERARCHY");
        iterator = list.iterator();
        while (iterator.hasNext()) {
            
            Map<?,?> listMap = (Map<?,?>)iterator.next();
            
            Number childSecurityRoleId = (Number)listMap.get("SECURITY_ROLE_ID");
            String childRoleName = roleMap.get(childSecurityRoleId);
            
            Number parentSecurityRoleId = (Number)listMap.get("INCLUDED_SECURITY_ROLE_ID");
            if (parentSecurityRoleId != null) {
                
                String parentRoleName = roleMap.get(parentSecurityRoleId);
                
                sb.append(childRoleName);
                sb.append(" > ");
                sb.append(parentRoleName);
                sb.append(" ");
            }
        }

        // The following role hierarchy segment is required to exist in order for the configuration/management operations to be invoked.
        String requiredRoles = IManagementService.JFW_SEC_CONFIG_ROLENAME
           + " "
           + IManagementService.ROLE_HIERARCHY_INCLUDES_DELIMITER
           + " "
           + IManagementService.JFW_SEC_MANAGEMENT_ROLENAME;

        // Ensure that the required security roles are present and in the proper hierarchy.
        this.roleHierarchyStringRepresentation = sb.toString();
        if (this.roleHierarchyStringRepresentation.isEmpty() && !this.roleHierarchyStringRepresentation.contains(requiredRoles)) {
            logger.error("Required Security Roles were not found in the database, using canonical default: " + requiredRoles);
            roleHierarchyStringRepresentation = requiredRoles;
        }
        
        logger.debug("Loaded role hierarchy from database and setting to be: " + roleHierarchyStringRepresentation);
        super.setHierarchy(this.roleHierarchyStringRepresentation);
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl#setHierarchy(java.lang.String)
     */
    synchronized public void setHierarchy(String roleHierarchyStringRepresentation) {
        
        if (roleHierarchyStringRepresentation == null) {
            
            if (logger.isDebugEnabled()) {
                logger.debug("Loading role hierarchy from database.");    
            }
            loadHierarchy();
            
        } else {
            
            if (!this.roleHierarchyStringRepresentation.equals(roleHierarchyStringRepresentation)) {

                if (logger.isDebugEnabled()) {
                    logger.debug("Setting role hierarchy to be: " + roleHierarchyStringRepresentation);    
                }
                super.setHierarchy(roleHierarchyStringRepresentation);
            }
        }
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl#getReachableGrantedAuthorities(java.util.Collection)
     */
    synchronized public Collection<GrantedAuthority> getReachableGrantedAuthorities(Collection<GrantedAuthority> authorities) {
        Collection<GrantedAuthority> reachableGrantedAuthorities = super.getReachableGrantedAuthorities(authorities);
        logger.debug("Reachable granted authorities for: " + authorities + " are: " + reachableGrantedAuthorities);
        return reachableGrantedAuthorities;
    }
}