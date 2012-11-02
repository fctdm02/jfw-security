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
package com.compuware.frameworks.security.service.server.management.ldap;

import org.apache.log4j.Logger;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;

import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;

/**
 * @author tmyers
 */
public final class ShadowSecurityUserContextMapper implements ContextMapper {

    /* */
    private final Logger logger = Logger.getLogger(ShadowSecurityUserContextMapper.class);
    
    /* */
    private String ldapUserUsernameAttribute;
    
    /* */
    private String ldapUserEmailAddressAttribute;
    
    /* */
    private String ldapUserFirstNameAttribute;
    
    /* */
    private String ldapUserLastNameAttribute;
    
    /* */
    private MultiTenancyRealm multiTenancyRealm;
    
    /**
     * 
     * @param ldapUserUsernameAttribute
     * @param ldapUserEmailAddressAttribute
     * @param ldapUserFirstNameAttribute
     * @param ldapUserLastNameAttribute
     * @param multiTenancyRealm
     */
    public ShadowSecurityUserContextMapper(
            String ldapUserUsernameAttribute,
            String ldapUserEmailAddressAttribute,
            String ldapUserFirstNameAttribute,
            String ldapUserLastNameAttribute,
            MultiTenancyRealm multiTenancyRealm) {
        
        this.ldapUserUsernameAttribute = ldapUserUsernameAttribute;
        this.ldapUserEmailAddressAttribute = ldapUserEmailAddressAttribute;
        this.ldapUserFirstNameAttribute = ldapUserFirstNameAttribute;
        this.ldapUserLastNameAttribute = ldapUserLastNameAttribute;
        this.multiTenancyRealm = multiTenancyRealm;
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.ldap.core.ContextMapper#mapFromContext(java.lang.Object)
     */
    public Object mapFromContext(Object ctx) {
        
        DirContextAdapter context = (DirContextAdapter)ctx;
        
        String userDn = context.getNameInNamespace();
        
        String username = (String)context.getStringAttribute(this.ldapUserUsernameAttribute);
        String shadowedFirstName = "";
        String shadowedLastName = "";
        String shadowedEmailAddress = "";
        
        if (!this.ldapUserEmailAddressAttribute.trim().equalsIgnoreCase("")) {
            shadowedEmailAddress = (String)context.getStringAttribute(this.ldapUserEmailAddressAttribute);
        }
        
        if (!this.ldapUserFirstNameAttribute.trim().equalsIgnoreCase("")) {
            shadowedFirstName = (String)context.getStringAttribute(this.ldapUserFirstNameAttribute);
        }

        if (!this.ldapUserLastNameAttribute.trim().equalsIgnoreCase("")) {
            shadowedLastName = (String)context.getStringAttribute(this.ldapUserLastNameAttribute);
        }
        
        // APMOSECURITY-145: Avoid entries in LDAP that are invalid.
        ShadowSecurityUser shadowSecurityUser = null;
        if (username != null && username.trim().length() > 0) {
            shadowSecurityUser = new ShadowSecurityUser(
                    username,
                    shadowedFirstName,
                    shadowedLastName,
                    shadowedEmailAddress,
                    userDn,
                    multiTenancyRealm);
        } else {
            logger.error("Invalid LDAP entry encountered, cannot create shadow security user for username: ["
                + username
                + "], first name: ["
                + shadowedFirstName
                + "], last name: "
                + shadowedLastName
                + "], email address: ["
                + shadowedEmailAddress
                + "].");
        }
                
        return shadowSecurityUser;
     }
}