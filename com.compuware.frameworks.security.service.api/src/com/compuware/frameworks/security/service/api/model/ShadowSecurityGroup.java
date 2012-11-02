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
package com.compuware.frameworks.security.service.api.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A class whose "groupname" field is both immutable and a 
 * "soft-reference" to the corresponding group in the external repository.  
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public final class ShadowSecurityGroup extends AbstractGroup {

	/* */
	private static final long serialVersionUID = 1L;

	/* */
	private String shadowedGroupLdapDN;
		
	/**
	 * 
	 */
	public ShadowSecurityGroup() {				
	}

	/**
	 * 
	 * @param groupname
	 * @param shadowedDescription
	 * @param shadowedGroupLdapDN
	 * @param multiTenancyRealm
	 */
    public ShadowSecurityGroup(
            String groupname,
            String shadowedDescription,
            String shadowedGroupLdapDN,
            MultiTenancyRealm multiTenancyRealm) {
        super(groupname, shadowedDescription, multiTenancyRealm);
        setShadowedGroupLdapDN(shadowedGroupLdapDN);
    }
	
	/**
	 * @return the shadowedGroupLdapDN
	 */
	@XmlElement
	public String getShadowedGroupLdapDN() {
		return shadowedGroupLdapDN;
	}

	/**
	 * @param shadowedGroupLdapDN the shadowedGroupLdapDN to set
	 */
	private void setShadowedGroupLdapDN(String shadowedGroupLdapDN) {
		this.shadowedGroupLdapDN = shadowedGroupLdapDN;
	}
}