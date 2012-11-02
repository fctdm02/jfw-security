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
package com.compuware.frameworks.security.service.server;

import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.core.context.SecurityContextHolder;

import com.compuware.frameworks.security.CompuwareSecurity;
import com.compuware.frameworks.security.CompuwareSecurityPropertyPlaceholderConfigurer;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityConfiguration;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityLdapConfiguration;
import com.compuware.frameworks.security.service.api.IServiceProvider;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.authentication.IAuthenticationService;
import com.compuware.frameworks.security.service.api.authorization.IAclManagerService;
import com.compuware.frameworks.security.service.api.configuration.IConfigurationService;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService;
import com.compuware.frameworks.security.service.api.migration.IMigrationService;
import com.compuware.frameworks.security.service.api.session.ISessionService;
import com.compuware.frameworks.security.service.server.authentication.ldap.LdapAuthenticator;
import com.compuware.frameworks.security.service.server.management.ldap.CompuwareSecurityLdapContextSource;

/**
 * Bootstrap bean class for JFW-Security "service.server" bundle.  This is used for clients that want to access services via the 
 * singleton instance here, that is accessible outside of Spring via the <code>ServiceProvider.getInstance()</code>                                                     
 * call. It is preferred, however, that clients use the Spring/OSGi approach            
 * (i.e. import the Spring beans as OSGi "services" that are exported here:<br>
 * <ul>             
 *   <li><b>OSGi Service ID</b> (Interface)
 *   <li>-----------------------------------------------
 *   <li><b>aclManagerServiceProxy</b> (com.compuware.frameworks.security.service.api.authorization.IAclManagerService)    
 *   <li><b>auditServiceProxy</b> (com.compuware.frameworks.security.service.api.audit.IAuditService)                            
 *   <li><b>authenticationServiceProxy</b> (com.compuware.frameworks.security.service.api.authentication.IAuthenticationService)
 *   <li><b>configurationServiceProxy</b> (com.compuware.frameworks.security.service.api.configuration.IConfigurationService)
 *   <li><b>ldapSearchServiceProxy</b> (com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService)
 *   <li><b>eventServiceProxy</b> (com.compuware.frameworks.security.service.api.event.IEventService)
 *   <li><b>managementServiceProxy</b> (com.compuware.frameworks.security.service.api.management.IManagementService)
 *   <li><b>migrationServiceProxy</b> (com.compuware.frameworks.security.service.api.migration.IMigrationService)
 *   <li><b>sessionServiceProxy</b> (com.compuware.frameworks.security.service.api.session.ISessionService)
 * </ul>                                                                                    
 * @author tmyers
 * 
 */
public final class ServiceProvider implements IServiceProvider, ApplicationContextAware {
    
    /** */
    public static final int MAX_WAIT_IN_SECONDS = 30;
    
    /** */
    public static final int WAIT_INTERVAL_IN_MILLIS = 1000;
        
    /* */
    private final static Logger LOGGER = Logger.getLogger(ServiceProvider.class);
            
    /* */
    private static AbstractApplicationContext applicationContext;
    
    /* */
    private static boolean isRefreshing;
    
    /* */
    private static boolean isPerformingMigration;

    /**
     * 
     * @param isPerformingMigration
     */
    public static synchronized void setIsPerformingMigration(boolean isPerformingMigration) {
        ServiceProvider.isPerformingMigration = isPerformingMigration;
    }

    /**
     * 
     * @return
     */
    public static synchronized boolean isPerformingMigration() {
        return ServiceProvider.isPerformingMigration;
    }
    
    /**
     * 
     * @return
     */
    public static IServiceProvider getInstance() {
        
        if (applicationContext == null) {
            int i = 0;
            while (applicationContext == null && i < MAX_WAIT_IN_SECONDS) {
                i = i + 1;
                LOGGER.error("Waiting for Compuware Security ServiceProvider to be initialized...");
                try {
                    Thread.sleep(WAIT_INTERVAL_IN_MILLIS);
                } catch (InterruptedException ie) {
                    throw new RuntimeException("Interrupted while waiting for Compuware Security ServiceProvider to be initialized...", ie);
                }
            }
        }
        if (applicationContext == null) {
            throw new RuntimeException("Compuware Security ServiceProvider timed out waiting for application context to be initialized...");
        }        
        return (IServiceProvider)applicationContext.getBean("serviceProvider"); 
    }
        
    /**
     * 
     */
    public ServiceProvider() {
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.context.ApplicationContextAware#setApplicationContext(org.springframework.context.ApplicationContext)
     */
    public synchronized void setApplicationContext(ApplicationContext applicationContextParameter) throws BeansException {
        
        LOGGER.info("Compuware Security ServiceProvider: initializing..." + applicationContextParameter);
        applicationContext = (AbstractApplicationContext)applicationContextParameter;
        System.setProperty("spring.security.strategy", SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getAclManagerService()
     */
    public IAclManagerService getAclManagerService() {
        return (IAclManagerService)applicationContext.getBean("aclManagerServiceProxy");
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getAuthenticationService()
     */
    public IAuditService getAuditService() {
        return (IAuditService)applicationContext.getBean("auditServiceProxy");
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getAuthenticationService()
     */
    public IAuthenticationService getAuthenticationService() {
        return (IAuthenticationService)applicationContext.getBean("authenticationServiceProxy");
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getConfigurationService()
     */
    public IConfigurationService getConfigurationService() {
        return (IConfigurationService)applicationContext.getBean("configurationServiceProxy");
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getEventService()
     */
    public IEventService getEventService() {
        return (IEventService)applicationContext.getBean("eventServiceProxy");
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getLdapSearchService()
     */
    public ILdapSearchService getLdapSearchService() {
        return (ILdapSearchService)applicationContext.getBean("ldapSearchServiceProxy");
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getManagementService()
     */
    public IManagementService getManagementService() {
        return (IManagementService)applicationContext.getBean("managementServiceProxy");
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getMigrationService()
     */
    public IMigrationService getMigrationService() {
        return (IMigrationService)applicationContext.getBean("migrationServiceProxy");
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getSessionService()
     */
    public ISessionService getSessionService() {
        return (ISessionService)applicationContext.getBean("sessionServiceProxy");
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#getRoleHierarchyImpl()
     */
    public RoleHierarchyImpl getRoleHierarchyImpl() {
        return (RoleHierarchyImpl)applicationContext.getBean("compuwareSecurityRoleHierarchyImpl"); 
    }
    
    /*
     * 
     * @param isRefreshing
     */
    private static synchronized void setIsRefreshing(boolean isRefreshing) {
        ServiceProvider.isRefreshing = isRefreshing;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#isRefreshing()
     */
    public synchronized boolean isRefreshing() {
        return ServiceProvider.isRefreshing;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.IServiceProvider#refresh()
     */
    public synchronized void refresh() {
        
        ServiceProvider.setIsRefreshing(true);
        
        ICompuwareSecurityConfiguration compuwareSecurityConfiguration = CompuwareSecurity.getInstance().getCompuwareSecurityConfiguration();
        CompuwareSecurityPropertyPlaceholderConfigurer propertyConfigurer = new CompuwareSecurityPropertyPlaceholderConfigurer(compuwareSecurityConfiguration);
        
        try {
            LOGGER.info("Refreshing LDAP related service layer beans...");
            String ldapUrl = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_URL_KEY);
            String ldapServiceAccountUsername = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_USERNAME_KEY);
            String ldapServiceAccountPassword = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_SERVICE_ACCOUNT_PASSWORD_KEY);
            String ldapReferral = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_REFERRAL_KEY);
            String ldapReferralLimit = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_REFERRAL_LIMIT_KEY);
            String ldapEncryptionMethod = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_ENCRYPTION_METHOD_KEY);
            String timeout = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_TIMEOUT_KEY);
            String useTls = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_USE_TLS_KEY);
            String performServerCertificateValidation = propertyConfigurer.resolvePlaceholder(ICompuwareSecurityLdapConfiguration.LDAP_USE_TLS_KEY);
            
            CompuwareSecurityLdapContextSource compuwareSecurityLdapContextSource = (CompuwareSecurityLdapContextSource)applicationContext.getBean("ldapContextSource");           
            Map<String, String> baseEnvironmentProperties = compuwareSecurityLdapContextSource.getBaseEnvironmentProperties();
            
            baseEnvironmentProperties.put("ldapUrl", ldapUrl);
            baseEnvironmentProperties.put("ldapServiceAccountUserDN", ldapServiceAccountUsername);
            baseEnvironmentProperties.put("ldapServiceAccountPassword", ldapServiceAccountPassword);
            baseEnvironmentProperties.put("ldapReferral", ldapReferral);
            baseEnvironmentProperties.put("java.naming.ldap.version", "3");
            baseEnvironmentProperties.put("java.naming.ldap.referral.limit", ldapReferralLimit);
            baseEnvironmentProperties.put("com.sun.jndi.ldap.read.timeout", timeout);
            baseEnvironmentProperties.put("com.sun.jndi.ldap.connect.timeout", timeout);
            baseEnvironmentProperties.put("java.naming.security.protocol", ldapEncryptionMethod);
            
            compuwareSecurityLdapContextSource.setUrl(ldapUrl);
            compuwareSecurityLdapContextSource.setUserDn(ldapServiceAccountUsername);
            compuwareSecurityLdapContextSource.setPassword(ldapServiceAccountPassword);
            compuwareSecurityLdapContextSource.setReferral(ldapReferral);
            compuwareSecurityLdapContextSource.setBaseEnvironmentProperties(baseEnvironmentProperties);
                        
            compuwareSecurityLdapContextSource = new CompuwareSecurityLdapContextSource(
                ldapUrl, 
                ldapServiceAccountUsername,
                ldapServiceAccountPassword,
                ldapReferral,
                useTls,
                performServerCertificateValidation,
                baseEnvironmentProperties);
            compuwareSecurityLdapContextSource.afterPropertiesSet();

            
            LdapAuthenticator ldapAuthenticator = (LdapAuthenticator)applicationContext.getBean("ldapAuthenticator");
            ldapAuthenticator.setContextSource(compuwareSecurityLdapContextSource);
            LOGGER.debug("Done refreshing LDAP related service layer beans...");
        } catch (Exception e) {
            throw new ServiceException("Could not refresh Spring beans for LDAP related configuration using properties: [" 
                    + compuwareSecurityConfiguration.getLdapConfiguration()
                    + "], error: " 
                    + e.getMessage(), e);                       
        } finally {
            ServiceProvider.setIsRefreshing(false);         
        }
    }
}