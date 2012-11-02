/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product emails are trademarks of their respective owners.
 * 
 * Copyright 2010 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.model;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;

import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
@XmlSeeAlso({SecurityGroup.class,ShadowSecurityGroup.class})
public abstract class AbstractGroup extends SecurityPrincipal {

   /** */
   private static final long serialVersionUID = 1L;
         
    /**
     * 
     */
    public AbstractGroup() {      
    }
    
    /**
     * @param groupname
     * @param description
     * @param multiTenancyRealm
     */
    public AbstractGroup(
            String groupname,
            String description,
            MultiTenancyRealm multiTenancyRealm) {
        this.setPrincipalName(groupname);
        this.setDescription(description);
        this.setMultiTenancyRealm(multiTenancyRealm);
    }
    
	/**
	 * @return the groupname
	 */
	public final String getGroupname() {
		return this.getPrincipalName();
	}

	/**
	 * @param groupname the groupname to set
	 */
	public final void setGroupname(String groupname) {
		this.setPrincipalName(groupname);
	}    
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
    */
   public void validate() throws ValidationException {

       super.validateMultiTenancyRealm();
      
       if (this.getGroupname() == null || this.getGroupname().isEmpty()) {
           throw new ValidationException(ValidationException.FIELD_GROUPNAME, ValidationException.REASON_CANNOT_BE_EMPTY);    
       }
   }
}