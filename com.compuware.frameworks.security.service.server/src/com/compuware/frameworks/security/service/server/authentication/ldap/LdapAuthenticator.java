/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2011 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.server.authentication.ldap;

import javax.naming.directory.DirContext;

import org.apache.log4j.Logger;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;
import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * Provides equivalent functionality to Spring's <code>BindAuthenticator</code> 
 * 
 * @author tmyers
 */
public final class LdapAuthenticator {

	/* */
	private final Logger logger = Logger.getLogger(LdapAuthenticator.class);
	
    /* */
    private ContextSource contextSource;
    
    /* */
    private ILdapSearchService ldapSearchService;

    /* */
    private IManagementService managementService;
    
    /* */
    private final static String BAD_CREDENTIALS_GIVEN = "Bad Credentials given.";

    /**
     * 
     * @param contextSource
     * @param ldapSearchService
     * @param managementService
     */
    public LdapAuthenticator(
        ContextSource contextSource,
        ILdapSearchService ldapSearchService,
        IManagementService managementService) {
        this.setContextSource(contextSource);
        this.setLdapSearchService(ldapSearchService);
        this.setManagementService(managementService);
    }
    
    /**
     * 
     * @param contextSource
     */
    public void setContextSource(ContextSource contextSource) {
        this.contextSource = contextSource;
    }
    
    /**
     * 
     * @param ldapSearchService
     */
    public void setLdapSearchService(ILdapSearchService ldapSearchService) {
        this.ldapSearchService = ldapSearchService;
    }
    
    /**
     * 
     * @param managementService
     */
    public void setManagementService(IManagementService managementService) {
        this.managementService = managementService;
    }
    
    /**
     * @return
     */
    public ContextSource getContextSource() {
    	return contextSource;
    }

    /**
     * 
     * @param authentication
     * @return successfully authenticated shadowSecurityUser
     * @throws InvalidConnectionException 
     */
    public ShadowSecurityUser authenticate(Authentication authentication) throws InvalidConnectionException {

        String infoMessage = null;
        String errorMessage = null;
        DirContext ctx = null;
        
        try {

            String realmName = ((CompuwareSecurityAuthenticationToken)authentication).getRealmName();
            MultiTenancyRealm multiTenancyRealm = null;
            if (realmName == null || realmName.isEmpty() || realmName.equals(IManagementService.DEFAULT_REALM_NAME)) {
                multiTenancyRealm = this.managementService.getDefaultMultiTenancyRealm();
            } else {
                try {
                    multiTenancyRealm = this.managementService.getMultiTenancyRealmByName(realmName);   
                } catch (ObjectNotFoundException onfe) {
                    throw new ServiceException("Could not find realm with realm name: " + realmName, onfe);
                }
            }

            String username = authentication.getName().toLowerCase();
            String password = authentication.getCredentials().toString();
            
            StringBuilder sb = new StringBuilder();
            sb.setLength(0);
            sb.append("Could not find LDAP user: [");
            sb.append(username);
            sb.append("], about to throw BadCredentialsException...");
            errorMessage = sb.toString();
            
            
            
            // STEP 1: Do a search using the LDAP Service Account to retrieve the user LDAP entry.
            ShadowSecurityUser shadowSecurityUser = this.ldapSearchService.getLdapUser(username, multiTenancyRealm);
            String userDn = shadowSecurityUser.getShadowedUserLdapDN();
                        
            sb.setLength(0);
            sb.append("Found LDAP user entry, attempting LDAP bind with DN and password for: [");
            sb.append(username);
            sb.append("].");
            infoMessage = sb.toString();
            logger.debug(infoMessage);
            
            
            
            // STEP 2: Do a bind with LDAP for the given LDAP User DN and password (this is the actual authentication).
            sb.append("Failed to bind/authenticate userDn/password for user DN: [");
            sb.append(userDn);
            sb.append("], about to throw BadCredentialsException...");
            errorMessage = sb.toString();
            
            DistinguishedName userDistinguishedName = new DistinguishedName(userDn);
            DistinguishedName fullDistinguishedName = new DistinguishedName(userDistinguishedName);
            
            // APMOSECURITY-151: Normally, the service layer would have rejected an authentication token with
            // an empty password, but since Gdansk wanted this hack for local users, we have to perform the 
            // check below, as AD apparently allows the bind when the password is empty.
            if (password == null || password.equals("")) {
                throw new BadCredentialsException(BAD_CREDENTIALS_GIVEN);
            }

            
            ctx = this.contextSource.getContext(fullDistinguishedName.toString(), password);
            
            
            
            // The LDAP user authenticated successfully, return the ShadowSecurityUser back to the authentication service.
            sb.setLength(0);
            sb.append("Successfully performed LDAP bind with DN and password for: [");
            sb.append(username);
            sb.append("].");
            infoMessage = sb.toString();
            logger.debug(infoMessage);
            return shadowSecurityUser;
            
        } catch (ValidationException ve) {
            logger.error(errorMessage, ve);
            throw new BadCredentialsException(BAD_CREDENTIALS_GIVEN, ve);
        } catch (org.springframework.ldap.AuthenticationException ae) {
            logger.error(ae.getMessage(), ae);
            throw new BadCredentialsException(BAD_CREDENTIALS_GIVEN, ae);            
        } catch (InvalidCredentialsException icrede) {
            logger.error(errorMessage, icrede);
            throw new BadCredentialsException(BAD_CREDENTIALS_GIVEN, icrede);
        } catch (ObjectNotFoundException onfe) {
            logger.error(errorMessage, onfe);
            throw new BadCredentialsException(BAD_CREDENTIALS_GIVEN, onfe);
        } catch (org.springframework.ldap.CommunicationException ce) {
            logger.error(ce.getMessage(), ce);
            throw new InvalidConnectionException("Could not communicate with the LDAP server: [" 
                + contextSource 
                + ", error: " 
                + ce.getMessage(), ce);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }
}