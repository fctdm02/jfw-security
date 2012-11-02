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
package com.compuware.frameworks.security.service.server.authentication;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.authentication.IAuthenticationCredentialCollector;
import com.compuware.frameworks.security.service.api.authentication.IAuthenticationService;
import com.compuware.frameworks.security.service.api.authentication.SystemUserAuthenticationHolder;
import com.compuware.frameworks.security.service.api.authentication.exception.AccountLockedException;
import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.authentication.exception.PasswordExpiredException;
import com.compuware.frameworks.security.service.api.configuration.IConfigurationService;
import com.compuware.frameworks.security.service.api.configuration.ILdapConfiguration;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;
import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.exception.NonDeletableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAccountLockedAuthenticationEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityInvalidCredentialsAuthenticationEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityPasswordExpiredAuthenticationEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySession;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySuccessfulAuthenticationEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityUserLoggedOutAuthenticationEvent;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityUser;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.SystemUser;
import com.compuware.frameworks.security.service.api.model.exception.MaxSessionsPerUserExceededException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;
import com.compuware.frameworks.security.service.server.AbstractService;
import com.compuware.frameworks.security.service.server.ServiceProvider;
import com.compuware.frameworks.security.service.server.authentication.jdbc.JdbcAuthoritiesPopulator;
import com.compuware.frameworks.security.service.server.authentication.ldap.LdapAuthenticator;
import com.compuware.frameworks.security.service.server.management.ldap.CompuwareSecuritySslSocketFactory;

/**
 * 
 * @author tmyers
 * 
 */
public final class AuthenticationServiceImpl extends AbstractService implements IAuthenticationService {

	/* */
	private Logger logger = Logger.getLogger(AuthenticationServiceImpl.class);

	
	/* */
	private static final String IN_REALM = " in realm: ";
			
		
	/* */
	private IManagementService managementService;
	
	/* */
	private IConfigurationService configurationService;	
	
	/* */
	private JdbcAuthoritiesPopulator jdbcAuthoritiesPopulator;
	
    /* */
    private LdapAuthenticator ldapAuthenticator;
    
	/* */
	private ILdapSearchService ldapSearchService;
	
	/**
	 * 
	 * @param auditService
	 * @param configurationService
	 * @param eventService
	 * @param managementService
	 * @param multiTenancyRealmDao
	 * @param ldapAuthenticator
	 * @param ldapSearchService
	 */
	public AuthenticationServiceImpl(
		IAuditService auditService,
		IConfigurationService configurationService,		
		IEventService eventService,
		IManagementService managementService,
		IMultiTenancyRealmDao multiTenancyRealmDao,
		LdapAuthenticator ldapAuthenticator,
		ILdapSearchService ldapSearchService) {
		super(auditService, eventService, multiTenancyRealmDao);
		setManagementService(managementService);
		setConfigurationService(configurationService);
		setLdapAuthenticator(ldapAuthenticator);
		setLdapSearchService(ldapSearchService);
		this.jdbcAuthoritiesPopulator = new JdbcAuthoritiesPopulator();
		this.jdbcAuthoritiesPopulator.setManagementService(managementService);
	}
	
	/**
	 * @param managementService the managementService to set
	 */
	public void setManagementService(IManagementService managementService) {
		this.managementService = managementService;
	}

	/**
	 * @param configurationService the configurationService to set
	 */
	public void setConfigurationService(IConfigurationService configurationService) {
		this.configurationService = configurationService;
	}
	
    /**
     * 
     * @param ldapAuthenticator
     */
    public void setLdapAuthenticator(LdapAuthenticator ldapAuthenticator) {
    	this.ldapAuthenticator = ldapAuthenticator;
    }

	/**
	 * @param ldapSearchService the ldapSearchService to set
	 */
	public void setLdapSearchService(ILdapSearchService ldapSearchService) {
		this.ldapSearchService = ldapSearchService;
	}

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.authentication.IAuthenticationService#deauthenticate()
     */
    public void deauthenticate() {
        
        boolean createAuditEvent = true;
        this.deauthenticate(createAuditEvent);
    }

    /*
     * 
     * @param createAuditEvent
     */
    private void deauthenticate(boolean createAuditEvent) {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        SecurityContextHolder.getContext().setAuthentication(null);
        
        if (createAuditEvent && authentication != null && authentication instanceof CompuwareSecurityAuthenticationToken) {
            CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken = (CompuwareSecurityAuthenticationToken)authentication;
            this.createAuditEvent(new CompuwareSecurityUserLoggedOutAuthenticationEvent(
                compuwareSecurityAuthenticationToken.getUserObject().getUsername(), 
                compuwareSecurityAuthenticationToken.getOriginatingIpAddress(), 
                compuwareSecurityAuthenticationToken.getOriginatingHostname(), 
                compuwareSecurityAuthenticationToken.getRealmName()));
        }        
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.authentication.IAuthenticationService#authenticate(com.compuware.frameworks.security.service.api.authentication.IAuthenticationCredentialCollector, java.lang.String, java.lang.String, java.lang.String)
     */
    public CompuwareSecurityAuthenticationToken authenticate(
        IAuthenticationCredentialCollector authenticationCredentialCollector,
        String realmName, 
        String originatingIpAddress, 
        String originatingHostname)
    throws 
        InvalidCredentialsException, 
        AccountLockedException, 
        PasswordExpiredException {
    
        CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationRequestToken = new CompuwareSecurityAuthenticationToken(
            authenticationCredentialCollector.getUsername(), 
            authenticationCredentialCollector.getPassword(), 
            originatingIpAddress,
            originatingHostname,
            realmName);
         
        return this.doAuthentication(compuwareSecurityAuthenticationRequestToken);
    }

   /*
    *  (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.authentication.IAuthenticationService#authenticate(java.lang.String, com.compuware.frameworks.security.service.api.model.ClearTextPassword, java.lang.String, java.lang.String, java.lang.String)
    */
   public CompuwareSecurityAuthenticationToken authenticate(
	   String username, 
	   ClearTextPassword clearTextPasswordParm, 
	   String realmName, 
	   String originatingIpAddress, 
	   String originatingHostname) 
   throws 
       InvalidCredentialsException, 
       AccountLockedException, 
       PasswordExpiredException {
       
       String clearTextPassword = null;
       if (clearTextPasswordParm != null) {
           clearTextPassword = clearTextPasswordParm.getClearTextPassword();
       }
	   
	   CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationRequestToken = new CompuwareSecurityAuthenticationToken(
	      username,
	      clearTextPassword,
	      originatingIpAddress,
	      originatingHostname,
	      realmName);
	   
	   return this.doAuthentication(compuwareSecurityAuthenticationRequestToken);
   }
	
    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.authentication.AuthenticationManager#
     * authenticate(org.springframework.security.core.Authentication)
     */
    public CompuwareSecurityAuthenticationToken authenticate(Authentication authentication) throws AuthenticationException {
        
        boolean isLdapAuthenticationEnabled = Boolean.parseBoolean(this.configurationService.getLdapConfiguration().getConfigurationValue(ILdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY)); 
        if (isLdapAuthenticationEnabled) {
            try {
                return this.doAuthentication(createCompuwareSecurityAuthenticationToken(authentication), isLdapAuthenticationEnabled);    
            } catch (Exception e) {
                // APM-SECURITY 54: Allow the ServiceException to be propagated up.
                if (e instanceof ServiceException && e.getMessage().startsWith(IAuthenticationService.DUPLICATE_ACCOUNTS_IN_LDAP_AND_LOCAL_CSS_REASON)) {
                    throw (ServiceException)e;
                }
                logger.error("authenticate(): LDAP Authentication failed for user: " + authentication.getName() + ", trying local authentication...");
                isLdapAuthenticationEnabled = false;
            }
        }
        
        try {
            return doAuthentication(createCompuwareSecurityAuthenticationToken(authentication), isLdapAuthenticationEnabled);
        } catch (InvalidCredentialsException e) {
            throw new ServiceException(e.getMessage(), e);
        } catch (InvalidConnectionException e) {
            throw new ServiceException(e.getMessage(), e);
        } catch (AccountLockedException e) {
            throw new ServiceException(e.getMessage(), e);
        } catch (PasswordExpiredException e) {
            throw new ServiceException(e.getMessage(), e);
        }
    }
    
    /*
     * 
     * @param authentication
     * @return
     * @throws InvalidCredentialsException
     * @throws InvalidConnectionException
     * @throws AccountLockedException
     * @throws PasswordExpiredException
     * @throws AuthenticationException
     */
    private CompuwareSecurityAuthenticationToken doAuthentication(
        CompuwareSecurityAuthenticationToken authentication) 
    throws 
        InvalidCredentialsException, 
        AccountLockedException, 
        PasswordExpiredException {
        
        boolean isLdapAuthenticationEnabled = Boolean.parseBoolean(this.configurationService.getLdapConfiguration().getConfigurationValue(ILdapConfiguration.IS_LDAP_AUTHENTICATION_ENABLED_KEY)); 
        if (isLdapAuthenticationEnabled) {
            
            try {
                return this.doAuthentication(authentication, isLdapAuthenticationEnabled);    
            } catch (Exception e) {
                // APM-SECURITY 54: Allow the ServiceException to be propagated up.
                if (e instanceof ServiceException && e.getMessage().startsWith(IAuthenticationService.DUPLICATE_ACCOUNTS_IN_LDAP_AND_LOCAL_CSS_REASON)) {
                    throw (ServiceException)e;
                }                
                logger.error("LDAP Authentication failed for user: " + authentication.getName() + ", trying local authentication...");
                isLdapAuthenticationEnabled = false;
            }
        }
        
        try {
            return doAuthentication(authentication, isLdapAuthenticationEnabled);    
        } catch (InvalidConnectionException ice) {
            // This should never occur as LDAP is disabled here. 
            throw new ServiceException(ice.getMessage(), ice);
        }
    }
    
    /*
     * 
     * @param authentication
     * @param isLdapAuthenticationEnabled
     * @return
     * @throws InvalidCredentialsException
     * @throws InvalidConnectionException
     * @throws AccountLockedException
     * @throws PasswordExpiredException
     */
    private CompuwareSecurityAuthenticationToken doAuthentication(
        CompuwareSecurityAuthenticationToken authenticationRequest,
        boolean isLdapAuthenticationEnabled) 
    throws 
        InvalidCredentialsException, 
        InvalidConnectionException, 
        AccountLockedException, 
        PasswordExpiredException {
        
        // Ensure that the security context is empty before we do anything.
        boolean createAuditEvent = false;
        this.deauthenticate(createAuditEvent);
                            
        String realmName = authenticationRequest.getRealmName();
        MultiTenancyRealm multiTenancyRealm = null;

        if (realmName == null || realmName.isEmpty() || realmName.equals(IManagementService.DEFAULT_REALM_NAME)) {
            realmName = IManagementService.DEFAULT_REALM_NAME;
            multiTenancyRealm = this.managementService.getDefaultMultiTenancyRealm();
        } else {
            try {
                multiTenancyRealm = this.managementService.getMultiTenancyRealmByName(realmName);   
            } catch (ObjectNotFoundException onfe) {
                throw new ServiceException(onfe.getMessage(), onfe);
            }
        }

        
        // In case we need to update the state of a SecurityUser (for invalid login attempts or locked account)
        // or to create a ShadowSecurityUser, we need to have a temporary authentication in the SecurityContextHolder
        // with Management privileges.
        CompuwareSecurityAuthenticationToken systemUserAuthenticationToken = SystemUserAuthenticationHolder.getSystemUserAuthenticationToken();
        if (systemUserAuthenticationToken == null) {
            systemUserAuthenticationToken = SystemUserAuthenticationHolder.getSecurityClientSystemUserAuthentication(realmName);
        }
        
                    
        String username = authenticationRequest.getName();
        
        String originatingIpAddress = authenticationRequest.getOriginatingIpAddress();
        if (originatingIpAddress == null || originatingIpAddress.isEmpty()) {
            throw new ServiceException(MISSING_ORIGINATING_IP_ADDRESS_IN_REQUEST_REASON);
        }
        
        String originatingHostname = authenticationRequest.getOriginatingHostname();                
        if (originatingHostname == null || originatingHostname.isEmpty()) {
            throw new ServiceException(MISSING_ORIGINATING_HOSTNAME_IN_REQUEST_REASON);
        }
                    
        // Force a reload of the role hierarchy for the given realm.
        managementService.loadRoleHierarchy(multiTenancyRealm);
            
        boolean createdShadowSecurityUser = false;
        AbstractUser abstractUser = null;
        try {
            
            abstractUser = managementService.getUserByUsername(username, multiTenancyRealm);
            
            // APM-SECURITY 54: If the username exists both locally as a SecurityUser *and* in LDAP, then throw a ServiceException
            // in order to avoid confusing runtime behavior.  The resolution is to delete/rename one of the two.
            if (abstractUser instanceof SecurityUser && isLdapAuthenticationEnabled) {
                try {
                    // At this point, we have local security user and an ldap user with the same username.  Throw a ServiceException 
                    // (per the problem description, https://dtw-jiraprod01.nasa.cpwr.corp:8443/browse/APMSECURITY-54)
                    this.ldapSearchService.getLdapUser(username, multiTenancyRealm);
                    throw new ServiceException(DUPLICATE_ACCOUNTS_IN_LDAP_AND_LOCAL_CSS_REASON);
                } catch (ValidationException ve) {
                    logger.error("Could not perform LDAP search for user: " + username + " because of a validation exception.", ve);
                } catch (ObjectNotFoundException onfe) {
                    // If we fall here, then it is perfectly OK, as the user in question may be for a local account. 
                }
            }
            
        } catch (ObjectNotFoundException onfe) {
            
            if (isLdapAuthenticationEnabled) {
                
                // Deal with first time LDAP users.
                try {
                    SecurityContextHolder.getContext().setAuthentication(systemUserAuthenticationToken);
                    logger.debug("Creating ShadowSecurityUser for LDAP username: " + username + IN_REALM + multiTenancyRealm);
                    abstractUser = this.managementService.createShadowSecurityUser(username, multiTenancyRealm);
                    createdShadowSecurityUser = true;
                } catch (ValidationException ve) {
                    throw new ServiceException("Could not create ShadowSecurityUser: " + username + IN_REALM + multiTenancyRealm, ve);
                } catch (ObjectAlreadyExistsException oaee) {
                    logger.error("Could not create shadow security user: " + username + IN_REALM + multiTenancyRealm, oaee);
                } finally {
                    SecurityContextHolder.getContext().setAuthentication(null);    
                }
                
            } else {
                
                this.createAuditEvent(new CompuwareSecurityInvalidCredentialsAuthenticationEvent(                           
                    username, 
                    originatingIpAddress, 
                    originatingHostname, 
                    multiTenancyRealm.getRealmName()));                
                throw new InvalidCredentialsException(IAuthenticationService.INVALID_CREDENTIALS_REASON);
            }
        }
                 
        try {
                            
            List<String> userLdapGroups = null;
            if ((isLdapAuthenticationEnabled && abstractUser instanceof ShadowSecurityUser) && abstractUser instanceof SystemUser == false) {
                
                ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
                String userDn = null;
                try {
                    Thread.currentThread().setContextClassLoader(CompuwareSecuritySslSocketFactory.class.getClassLoader());
                    
                    ShadowSecurityUser authenticatedShadowSecurityUser = this.ldapAuthenticator.authenticate(authenticationRequest);
                    if (abstractUser instanceof ShadowSecurityUser) {
                        
                        ((ShadowSecurityUser)abstractUser).setShadowedFirstName(authenticatedShadowSecurityUser.getShadowedFirstName());
                        ((ShadowSecurityUser)abstractUser).setShadowedLastName(authenticatedShadowSecurityUser.getShadowedLastName());
                        ((ShadowSecurityUser)abstractUser).setShadowedEmailAddress(authenticatedShadowSecurityUser.getShadowedEmailAddress());
                    }
                    userDn = authenticatedShadowSecurityUser.getShadowedUserLdapDN();
                    userLdapGroups = this.ldapSearchService.getLdapGroupsForLdapUserDn(userDn, multiTenancyRealm);
                } finally {
                    Thread.currentThread().setContextClassLoader(oldClassLoader);
                    
                    if (userDn == null && createdShadowSecurityUser) {
                        try {
                            SecurityContextHolder.getContext().setAuthentication(systemUserAuthenticationToken);
                            logger.debug("Deleting bogus ShadowSecurityUser for LDAP username: " + username + IN_REALM + multiTenancyRealm);
                            this.managementService.deleteShadowSecurityUser(username, multiTenancyRealm);
                        } catch (NonDeletableObjectException ndoe) {
                            throw new ServiceException("Could not delete bogus ShadowSecurityUser: " + username + IN_REALM + multiTenancyRealm, ndoe);                                
                        } catch (ObjectNotFoundException onfe) {
                            throw new ServiceException("Could not delete bogus ShadowSecurityUser: " + username + IN_REALM + multiTenancyRealm, onfe);
                        } finally {
                            SecurityContextHolder.getContext().setAuthentication(null);    
                        }
                    }
                }
            } else {
                
                if (authenticationRequest.getCredentials() != null) {
                    
                    String clearTextPassword = authenticationRequest.getCredentials().toString();
                    if (abstractUser instanceof SecurityUser) {
                        
                        SecurityUser securityUser = (SecurityUser)abstractUser;
                        if (!securityUser.isAccountNonLocked()) {
                            this.createAuditEvent(new CompuwareSecurityAccountLockedAuthenticationEvent(
                                username, 
                                originatingIpAddress, 
                                originatingHostname, 
                                multiTenancyRealm.getRealmName()));
                            throw new AccountLockedException(ACCOUNT_HAS_BEEN_DEACTIVATED_REASON);
                        }

                        // See if the user entered the password correctly.
                        boolean isPasswordCorrect = false;
                        try {
                            isPasswordCorrect = managementService.authenticateSecurityUser(clearTextPassword, securityUser);
                        } catch (ValidationException ve) {
                            throw new ServiceException("Could not encode password given in authentication request for username: " + username, ve);  
                        }
                        
                        if (!isPasswordCorrect) {
                            
                            // Deal with the invalid login attempts.  Ignore if the max value is -1.
                            int maxNumberUnsuccessfulLoginAttempts = multiTenancyRealm.getActivePasswordPolicy().getMaxNumberUnsuccessfulLoginAttempts();
                            if (maxNumberUnsuccessfulLoginAttempts != -1) {

                                int numberUnsucccessfulLoginAttempts = securityUser.getNumberUnsucccessfulLoginAttempts();
                                
                                // Once the user has reached the max number of invalid logins, it is pointless to increment further.
                                if (numberUnsucccessfulLoginAttempts < maxNumberUnsuccessfulLoginAttempts) {
                                    
                                    securityUser.incrementNumberUnsucccessfulLoginAttempts();
                                    
                                    try {
                                        SecurityContextHolder.getContext().setAuthentication(systemUserAuthenticationToken);
                                        this.managementService.updateSecurityUser(securityUser);    
                                    } catch (Exception e) {
                                        logger.error("Could not increment unsuccessful login attempts for user: " + securityUser, e);
                                    } finally {
                                        SecurityContextHolder.getContext().setAuthentication(null);    
                                    }
                                }
                                    
                                // If the user has reached the limit for invalid logins, then disallow login.
                                if (numberUnsucccessfulLoginAttempts >= maxNumberUnsuccessfulLoginAttempts) {

                                    logger.error("User: " + username + " has exceeded max number of login attempts, disallowing login and throwing AccountLockedException.");
                                    this.createAuditEvent(new CompuwareSecurityAccountLockedAuthenticationEvent(
                                        username, 
                                        originatingIpAddress, 
                                        originatingHostname, 
                                        " number unsuccessful login attempts: " + securityUser.getNumberUnsucccessfulLoginAttempts(),
                                        multiTenancyRealm.getRealmName()));
                                    throw new AccountLockedException(ACCOUNT_HAS_NUMBER_INVALID_LOGINS_EXCEEDED_REASON);
                                }
                            }
                                    
                            this.createAuditEvent(new CompuwareSecurityInvalidCredentialsAuthenticationEvent(                           
                                username, 
                                originatingIpAddress, 
                                originatingHostname, 
                                multiTenancyRealm.getRealmName()));
                            throw new InvalidCredentialsException(IAuthenticationService.INVALID_CREDENTIALS_REASON);
                            
                        } else {
                            // If the user's password is expired, then don't allow them to login.
                            if (!securityUser.isCredentialsNonExpired()) {
                                this.createAuditEvent(new CompuwareSecurityPasswordExpiredAuthenticationEvent(
                                    username, 
                                    originatingIpAddress, 
                                    originatingHostname, 
                                    multiTenancyRealm.getRealmName()));
                                throw new PasswordExpiredException(PASSWORD_HAS_EXPIRED_REASON);
                            }
                            
                            // Successful login for a security user.  If their 'invalid login attempts' is non-zero, then reset it now.
                            int numberUnsucccessfulLoginAttempts = securityUser.getNumberUnsucccessfulLoginAttempts();
                            if (numberUnsucccessfulLoginAttempts > 0) {
                                try {
                                    securityUser.setNumberUnsucccessfulLoginAttempts(0);
                                    SecurityContextHolder.getContext().setAuthentication(systemUserAuthenticationToken);                                    
                                    this.managementService.updateSecurityUser(securityUser);    
                                } catch (Exception e) {
                                    logger.error("Could not reset invalid login attempts for user back to zero: " + securityUser, e);
                                } finally {
                                    SecurityContextHolder.getContext().setAuthentication(null);    
                                }                                
                            }
                        }
                    } else if (abstractUser instanceof SystemUser) {   
                        
                        // See if the system user password that was given is correct or not.
                        boolean isPasswordCorrect = false;
                        try {
                            isPasswordCorrect = managementService.authenticateSystemUser(clearTextPassword, (SystemUser)abstractUser);
                        } catch (ValidationException ve) {
                            throw new ServiceException("Could not encode password given in authentication request for username: " + username, ve);  
                        }
                        if (!isPasswordCorrect) {
                            
                            this.createAuditEvent(new CompuwareSecurityInvalidCredentialsAuthenticationEvent(                           
                                username, 
                                originatingIpAddress, 
                                originatingHostname, 
                                multiTenancyRealm.getRealmName()));
                            throw new InvalidCredentialsException(IAuthenticationService.INVALID_CREDENTIALS_REASON);
                        }                            
                    } else {
                        this.createAuditEvent(new CompuwareSecurityInvalidCredentialsAuthenticationEvent(                           
                            username, 
                            originatingIpAddress, 
                            originatingHostname, 
                            multiTenancyRealm.getRealmName()));
                        throw new InvalidCredentialsException(IAuthenticationService.INVALID_CREDENTIALS_REASON);
                    }                        
                } else {
                    this.createAuditEvent(new CompuwareSecurityInvalidCredentialsAuthenticationEvent(                           
                        username, 
                        originatingIpAddress, 
                        originatingHostname, 
                        multiTenancyRealm.getRealmName()));
                    throw new InvalidCredentialsException(IAuthenticationService.INVALID_CREDENTIALS_REASON);
                }
            }
            
            Collection<GrantedAuthority> authorities = null;
            try {
                authorities = jdbcAuthoritiesPopulator.getGrantedAuthorities(abstractUser, userLdapGroups);
            } catch (ObjectNotFoundException onfe) {
                throw new ServiceException(onfe.getMessage(), onfe);
            }

            CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationResponseToken = new CompuwareSecurityAuthenticationToken(
                abstractUser, 
                authorities, 
                new java.util.Date(System.currentTimeMillis()),
                authenticationRequest.getOriginatingIpAddress(),
                authenticationRequest.getOriginatingHostname());
            
           SecurityContextHolder.getContext().setAuthentication(compuwareSecurityAuthenticationResponseToken);
            
           this.createAuditEvent(new CompuwareSecuritySuccessfulAuthenticationEvent(
                username, 
                originatingIpAddress, 
                originatingHostname, 
                multiTenancyRealm.getRealmName()));
            
            return compuwareSecurityAuthenticationResponseToken;
            
        } catch (BadCredentialsException bce) { // LDAP

            InvalidCredentialsException ice = new InvalidCredentialsException(IAuthenticationService.INVALID_CREDENTIALS_REASON, bce);
            
            this.createAuditEvent(new CompuwareSecurityInvalidCredentialsAuthenticationEvent(                           
                    username, 
                    originatingIpAddress, 
                    originatingHostname, 
                    multiTenancyRealm.getRealmName()));                
            
            throw ice;              
            
        } catch (UsernameNotFoundException unfe) { // LDAP
            
            InvalidCredentialsException ice = new InvalidCredentialsException(IAuthenticationService.INVALID_CREDENTIALS_REASON, unfe);
            
            this.createAuditEvent(new CompuwareSecurityInvalidCredentialsAuthenticationEvent(                           
                username, 
                originatingIpAddress, 
                originatingHostname, 
                multiTenancyRealm.getRealmName()));                
            
            throw ice;
        }               
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationProvider#supports(java.lang.Class)
     */
    public boolean supports(Class<? extends Object> authentication) {
        
        if (authentication.getClass().toString().equals(CompuwareSecurityAuthenticationToken.class.getClass().toString())) {
            return true;    
        }
        logger.warn("Authentication token not supported: " 
           + authentication.getClass().toString() 
           + "], only instances of: [" 
           + CompuwareSecurityAuthenticationToken.class.getClass().toString() 
           + "] are.");
        return false;
    }
    
    /*
     * @param authentication
     * @return
     */
    private CompuwareSecurityAuthenticationToken createCompuwareSecurityAuthenticationToken(Authentication authentication) {
        
        CompuwareSecurityAuthenticationToken authenticationRequest = null;
        if (authentication instanceof CompuwareSecurityAuthenticationToken) {
            authenticationRequest = (CompuwareSecurityAuthenticationToken)authentication;    
        } else {
            
            String realmName = IManagementService.DEFAULT_REALM_NAME;
            Object credentials = authentication.getCredentials();
            String password = null;
            if (credentials != null) {
                if (credentials instanceof ClearTextPassword) {
                    password = ((ClearTextPassword)credentials).getClearTextPassword();
                } else {
                    password = credentials.toString();
                }
            }
                        
            try {
                authenticationRequest = new CompuwareSecurityAuthenticationToken(
                        authentication.getName(),
                        password,
                        InetAddress.getLocalHost().getHostAddress(), 
                        InetAddress.getLocalHost().getHostName(),
                        realmName);
            } catch (UnknownHostException uhe) {
                throw new ServiceException("Could not determine localhost hostname/address, error: " + uhe.getMessage(), uhe);
            }
        }
        return authenticationRequest;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.authentication.IAuthenticationService#authenticateWithSessionCreation(java.lang.String, com.compuware.frameworks.security.service.api.model.ClearTextPassword, java.lang.String, java.lang.String, java.lang.String)
     */
    public CompuwareSecuritySession authenticateWithSessionCreation(
        String username, 
        ClearTextPassword clearTextPassword,
        String realmName,
        String originatingIpAddress, 
        String originatingHostname) 
    throws 
        InvalidCredentialsException, 
        AccountLockedException, 
        PasswordExpiredException,
        MaxSessionsPerUserExceededException {
        
        CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken = this.authenticate(
            username, 
            clearTextPassword, 
            realmName,
            originatingIpAddress, 
            originatingHostname);
        
        return ServiceProvider.getInstance().getSessionService().createAndReturnSession(compuwareSecurityAuthenticationToken);
    }
}