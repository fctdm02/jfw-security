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
package com.compuware.frameworks.security.service.server.interceptor;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.log4j.Logger;

import com.compuware.frameworks.security.service.api.configuration.IConfigurationService;
import com.compuware.frameworks.security.service.api.management.ldap.ILdapSearchService;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.server.ServiceProvider;

/**
 * This interceptor is injected into the list of interceptors for the 
 * <code>IManagementService</code> proxy and ensures that any <code>ShadowSecurityUser</code>
 * instances are populated with respect to the following fields:
 * <ul>
 * <li>First Name</li>
 * <li>Last Name</li>
 * <li>Email Address</li>
 * <p>
 * A <code>WeakHashMap</code> is maintained for use as a cache (keyed by <code>username</code>
 * and is consulted for any parameters and return objects that are of type 
 * <code>ShadowSecurityUser</code>.  When this is the case, if the cache entry is null, then  
 * the <code>ILdapSearchService</code> is used to retrieve a filled <code>ShadowSecurityUser</code>
 * instance (which, is transient).  The first name, last name and email address properties are set 
 * in the persistent instance (which is either in a collection or the object being returned)
 * <p>
 * Over time, this cache will get hot and all methods requesting LDAP users will be satisified by
 * this interceptor. 
 *  
 * @author tmyers
 */
public class CompuwareSecurityShadowSecurityUserInterceptor implements MethodInterceptor {

    /* */
    private final Logger logger = Logger.getLogger(CompuwareSecurityShadowSecurityUserInterceptor.class);
    
    /* */
    private static final Map<String, ShadowSecurityUser> SHADOW_SECURITY_USER_CACHE = new WeakHashMap<String, ShadowSecurityUser>();
    
    /*
     * (non-Javadoc)
     * @see org.aopalliance.intercept.MethodInterceptor#invoke(org.aopalliance.intercept.MethodInvocation)
     */
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        
        // Call the business method that we are intercepting.
        Object returnValue = methodInvocation.proceed();

        // We don't do this for createShadowSecurityUser().
        String methodName = methodInvocation.getMethod().getName();
        if (!methodName.startsWith("createShadowSecurityUser")) {
            
            // We only do lookups for ShadowSecurityUsers if LDAP Authentication is enabled 
            // (Which is the only way we know for sure that LDAP is properly configured)
            IConfigurationService configurationService = ServiceProvider.getInstance().getConfigurationService();
            Boolean enableLdapAuthentication = Boolean.parseBoolean(configurationService.getLdapConfiguration().getEnableLdapAuthentication());
            if (enableLdapAuthentication.equals(Boolean.TRUE)) {

                // This is what we use to get a fully populated LDAP user.
                ILdapSearchService ldapSearchService = ServiceProvider.getInstance().getLdapSearchService();        
                
                // See if the return object is, or contains, a ShadowSecurityUser.  Either way, make sure that any ShadowSecurityUser has
                // their first name, last name and email address fields populated from our "populated shadow security user" cache.  
                // If the shadow security user is not in the cache, then retrieve it from LDAP and add to the cache.
                if (returnValue instanceof ShadowSecurityUser) {
                    
                    populateShadowSecurityUser((ShadowSecurityUser)returnValue, ldapSearchService);
                    
                } else if (returnValue instanceof Collection) {
                    
                    Collection<?> collection = (Collection<?>)returnValue;
                    Iterator<?> iterator = collection.iterator();
                    while (iterator.hasNext()) {
                        
                        Object object = iterator.next();
                        if (object instanceof ShadowSecurityUser) {
                            
                            populateShadowSecurityUser((ShadowSecurityUser)object, ldapSearchService);
                        }
                    }
                }
            }
        }
                           
        return returnValue;
    }
    
    /*
     * 
     * @param shadowSecurityUser
     * @param ldapSearchService
     */
    private void populateShadowSecurityUser(ShadowSecurityUser shadowSecurityUser, ILdapSearchService ldapSearchService) {
        
        ShadowSecurityUser populatedShadowSecurityUser = SHADOW_SECURITY_USER_CACHE.get(shadowSecurityUser.getUsername());
        if (populatedShadowSecurityUser == null) {

            try {
                populatedShadowSecurityUser = ldapSearchService.getLdapUser(
                        shadowSecurityUser.getUsername(), 
                        shadowSecurityUser.getMultiTenancyRealm());
                    
                SHADOW_SECURITY_USER_CACHE.put(shadowSecurityUser.getUsername(), populatedShadowSecurityUser);
            } catch (Exception e) {
                logger.error("Could not retrieve shadow security user details from LDAP for user: " + shadowSecurityUser, e );
            }                
        }
        
        if (populatedShadowSecurityUser != null) {

            shadowSecurityUser.setShadowedFirstName(populatedShadowSecurityUser.getShadowedFirstName());
            shadowSecurityUser.setShadowedLastName(populatedShadowSecurityUser.getShadowedLastName());
            shadowSecurityUser.setShadowedEmailAddress(populatedShadowSecurityUser.getShadowedEmailAddress());
            shadowSecurityUser.setShadowedUserLdapDN(populatedShadowSecurityUser.getShadowedUserLdapDN());
        }
    }
}