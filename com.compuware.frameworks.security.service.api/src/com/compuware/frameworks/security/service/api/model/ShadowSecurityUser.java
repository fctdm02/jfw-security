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

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A class whose "username" field is both immutable and a 
 * "soft-reference" to the corresponding user in the external repository.  
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public class ShadowSecurityUser extends AbstractUser {

	/* */
	private static final long serialVersionUID = 1L;
	
	/* */
	private String shadowedFirstName;
	
	/* */
	private String shadowedLastName;
	
	/* */
	private String shadowedEmailAddress;
	
	/* */
	private String shadowedUserLdapDN;
	
	/* */
	private List<ShadowSecurityGroup> userLdapGroups = new ArrayList<ShadowSecurityGroup>();
	
    /**
	 * 
	 */
	public ShadowSecurityUser() {				
	}
	
	/**
	 * @param username
	 * @param shadowedFirstName
	 * @param shadowedLastName
	 * @param shadowedEmailAddress
	 * @param shadowedUserLdapDN
	 * @param multiTenancyRealm
	 */
	public ShadowSecurityUser(
	        String username,
			String shadowedFirstName,
			String shadowedLastName,
			String shadowedEmailAddress,
			String shadowedUserLdapDN,
			MultiTenancyRealm multiTenancyRealm) {
	    super(username, multiTenancyRealm);
        this.shadowedFirstName = shadowedFirstName;
        this.shadowedLastName = shadowedLastName;
        this.shadowedEmailAddress = shadowedEmailAddress;
        this.shadowedUserLdapDN = shadowedUserLdapDN;
	}

    /**
     * @param username
     * @param shadowedFirstName
     * @param shadowedLastName
     * @param shadowedEmailAddress
     * @param shadowedUserLdapDN
     * @param userLdapGroups
     * @param multiTenancyRealm
     */
    public ShadowSecurityUser(
            String username,
            String shadowedFirstName,
            String shadowedLastName,
            String shadowedEmailAddress,
            String shadowedUserLdapDN,
            List<ShadowSecurityGroup> userLdapGroups,
            MultiTenancyRealm multiTenancyRealm) {
        super(username, multiTenancyRealm);
        this.shadowedFirstName = shadowedFirstName;
        this.shadowedLastName = shadowedLastName;
        this.shadowedEmailAddress = shadowedEmailAddress;
        this.shadowedUserLdapDN = shadowedUserLdapDN;
        this.userLdapGroups = userLdapGroups;
    }
	
	/**
	 * @return the shadowedFirstName
	 */
    @XmlElement
	public final String getShadowedFirstName() {
		return shadowedFirstName;
	}

	/**
	 * @return the shadowedLastName
	 */
    @XmlElement
	public final String getShadowedLastName() {
		return shadowedLastName;
	}

	/**
	 * @return the shadowedEmailAddress
	 */
    @XmlElement
	public final String getShadowedEmailAddress() {
		return shadowedEmailAddress;
	}

	/**
	 * @return the shadowedUserLdapDN
	 */
    @XmlElement
	public final String getShadowedUserLdapDN() {
		return shadowedUserLdapDN;
	}

	/**
	 * 
	 * @return
	 */
	@XmlElementWrapper(name="shadowSecurityGroupSet")
	@XmlElement(name="shadowSecurityGroup")
    public List<ShadowSecurityGroup> getUserLdapGroups() {
        return userLdapGroups;
    }
	
	/**
     * @param shadowedFirstName the shadowedFirstName to set
     */
    public final void setShadowedFirstName(String shadowedFirstName) {
        this.shadowedFirstName = shadowedFirstName;
    }

    /**
     * @param shadowedLastName the shadowedLastName to set
     */
    public final void setShadowedLastName(String shadowedLastName) {
        this.shadowedLastName = shadowedLastName;
    }

    /**
     * @param shadowedEmailAddress the shadowedEmailAddress to set
     */
    public final void setShadowedEmailAddress(String shadowedEmailAddress) {
        this.shadowedEmailAddress = shadowedEmailAddress;
    }

    /**
     * @param shadowedUserLdapDN the shadowedUserLdapDN to set
     */
    public final void setShadowedUserLdapDN(String shadowedUserLdapDN) {
        this.shadowedUserLdapDN = shadowedUserLdapDN;
    }

    /**
     * @param userLdapGroups the userLdapGroups to set
     */
    public final void setUserLdapGroups(List<ShadowSecurityGroup> userLdapGroups) {
        this.userLdapGroups = userLdapGroups;
    }

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.AbstractUser#getEncodedPassword()
	 */
	public final String getEncodedPassword() {
		throw new IllegalStateException("A ShadowSecurityUser does not have a password, this method should not be called.");
	}
}