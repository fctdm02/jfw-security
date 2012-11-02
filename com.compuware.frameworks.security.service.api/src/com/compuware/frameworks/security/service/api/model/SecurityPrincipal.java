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

import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * Instances of SecurityUsers and Groups represent objects that are the "master of record" 
 * ("Local" Authentication Mode) - in which the user attributes such as email 
 * address and passwords have meaning.
 * <p>
 * Instances of LdapShadowSecurityUsers and LdapShadowGroups represent objects that are 
 * "shadow records" of what is in LDAP ("Customer LDAP" Authentication Mode) - 
 * and are shallow copies of what is in the customer LDAP (usually just the principalName only, 
 * as all other attributes are looked up in LDAP directly. 
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public abstract class SecurityPrincipal extends DomainObject {

	/** */
	private static final long serialVersionUID = 1L;
		

    /** */
    private Long securityPrincipalId;
   
    /** */
    private String principalName;

	/** */
	private String description;
		
	/** 
	 * Used to facilitate multi-tenancy.  Each domain object must belong to a multi-tenancy "realm".  If any unique constraints are
	 * created on 'name' fields, then those constraints need to incorporate the realm.  e.g. 'principalName' on the 'SecurityPrincipal' table
	 * should have a unique index created that is a combination of principalName and the multiTenancyRealm foreign key.
	 */
	private MultiTenancyRealm multiTenancyRealm;

	/**
	 */
	public SecurityPrincipal() {		
	}

   /**
    * @return the securityPrincipalId
    */
   @XmlElement
   public final Long getSecurityPrincipalId() {
      return securityPrincipalId;
   }

   /**
    * @param securityPrincipalId the securityPrincipalId to set
    */
   public final void setSecurityPrincipalId(Long securityPrincipalId) {
      this.securityPrincipalId = securityPrincipalId;
   }
   
   /**
    * @return the principalName
    */
   @XmlElement
   public final String getPrincipalName() {
       return this.principalName;
   }

   /**
    * @param principalName the principalName to set
    */
   public final void setPrincipalName(String principalName) {
       this.principalName = DomainObject.trimString(principalName);
   }
   
	/**
	 * @return the description
	 */
	@XmlElement
	public final String getDescription() {
	    return DomainObject.getOptionalStringValue(description);
	}

	/**
	 * @param description the description to set
	 */
	public final void setDescription(String description) {
	   this.description = DomainObject.trimString(description);
	}
	
	/**
	 * @return the multiTenancyRealm
	 */
	@XmlElement
	public final MultiTenancyRealm getMultiTenancyRealm() {
		return multiTenancyRealm;
	}

	/**
	 * @param multiTenancyRealm the multiTenancyRealm to set
	 */
	public final void setMultiTenancyRealm(MultiTenancyRealm multiTenancyRealm) {
		this.multiTenancyRealm = multiTenancyRealm;
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getPersistentIdentity()
    */
   public final Long getPersistentIdentity() {
	   
      return getSecurityPrincipalId();
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getNaturalIdentity()
    */
   public final String getNaturalIdentity() {
       return this.principalName;
   }
   
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#toString()
	 */
	public final String toString() {
		
		return this.getPrincipalName();
	}
	
	/*
	 * 
	 * @throws ValidationException
	 */
	protected final void validateMultiTenancyRealm() throws ValidationException {
	    
       if (this.multiTenancyRealm == null) {
           throw new ValidationException(ValidationException.FIELD_MULTI_TENANCY_REALM, ValidationException.REASON_CANNOT_BE_NULL);
       }
	}
}