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

import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;

import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;

/**
 * @author tmyers
 */
public final class ShadowSecurityGroupContextMapper implements ContextMapper {

    /* */
    private String ldapGroupGroupnameAttribute;
    
    /* */
    private String ldapGroupDescriptionAttribute;
    
    /* */
    private MultiTenancyRealm multiTenancyRealm;
    
    /**
     * 
     * @param ldapGroupGroupnameAttribute
     * @param ldapGroupDescriptionAttribute
     * @param multiTenancyRealm
     */
    public ShadowSecurityGroupContextMapper(
            String ldapGroupGroupnameAttribute,
            String ldapGroupDescriptionAttribute,
            MultiTenancyRealm multiTenancyRealm) {

        this.ldapGroupGroupnameAttribute = ldapGroupGroupnameAttribute;
        this.ldapGroupDescriptionAttribute = ldapGroupDescriptionAttribute;
        this.multiTenancyRealm = multiTenancyRealm;
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.ldap.core.ContextMapper#mapFromContext(java.lang.Object)
     */
    public Object mapFromContext(Object ctx) {
        
        DirContextAdapter context = (DirContextAdapter)ctx;
        
        String groupDn = context.getNameInNamespace();
        
        String groupname = (String)context.getStringAttribute(this.ldapGroupGroupnameAttribute);        
        String shadowedGroupDescription = "";
        
        if (!this.ldapGroupDescriptionAttribute.trim().equalsIgnoreCase("")) {
            shadowedGroupDescription = (String)context.getStringAttribute(this.ldapGroupDescriptionAttribute);
        }
        
        ShadowSecurityGroup shadowSecurityGroup = new ShadowSecurityGroup(
                groupname,
                shadowedGroupDescription,
                groupDn,
                multiTenancyRealm);
        
        return shadowSecurityGroup;
     }
}