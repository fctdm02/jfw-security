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
package com.compuware.frameworks.security.service.api;

import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;

import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.authentication.IAuthenticationService;
import com.compuware.frameworks.security.service.api.authorization.IAclManagerService;
import com.compuware.frameworks.security.service.api.configuration.IConfigurationService;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService;
import com.compuware.frameworks.security.service.api.migration.IMigrationService;
import com.compuware.frameworks.security.service.api.session.ISessionService;

/**
 * 
 * @author tmyers
 * 
 */
public interface IServiceProvider {

	/**
	 * 
	 * @return IAclManagerService
	 */
	IAclManagerService getAclManagerService();
	
	/**
	 * 
	 * @return IAuditService
	 */
	IAuditService getAuditService();
	
	/**
	 * 
	 * @return IAuthenticationService
	 */
	IAuthenticationService getAuthenticationService();
	
	/**
	 * 
	 * @return IConfigurationService
	 */
	IConfigurationService getConfigurationService();
	
	/**
	 * 
	 * @return IEventService
	 */
	IEventService getEventService();

    /**
     * 
     * @return ILdapSearchService
     */
    ILdapSearchService getLdapSearchService();
	
	/**
	 * 
	 * @return IManagementService
	 */
	IManagementService getManagementService();
	
	/**
	 * 
	 * @return IMigrationService
	 */
	IMigrationService getMigrationService();

    /**
     * 
     * @return ISessionService
     */
    ISessionService getSessionService();
	
	/**
	 * 
	 * @return RoleHierarchyImpl
	 */
	RoleHierarchyImpl getRoleHierarchyImpl();
	
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
}