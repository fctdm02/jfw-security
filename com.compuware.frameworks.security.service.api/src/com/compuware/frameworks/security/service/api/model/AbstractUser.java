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
@XmlSeeAlso({SecurityUser.class,ShadowSecurityUser.class,SystemUser.class})
public abstract class AbstractUser extends SecurityPrincipal {

   /** */
   private static final long serialVersionUID = 1L;
         
    /**
     * 
     */
    public AbstractUser() {      
    }

    /**
     * @param username
     * @param multiTenancyRealm
     */
    public AbstractUser(String username, MultiTenancyRealm multiTenancyRealm) {
        this.setPrincipalName(username);
        this.setMultiTenancyRealm(multiTenancyRealm);
    }
    
   /**
    * 
    * @return username
    */
   public final String getUsername() {
	   return this.getPrincipalName();
   }
         
   /**
    * @param username
    */
   public final void setUsername(String username) {
	   this.setPrincipalName(username);
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
    */
   public void validate() throws ValidationException {

       super.validateMultiTenancyRealm();
      
       if (this.getUsername() == null || this.getUsername().isEmpty()) {
           throw new ValidationException(ValidationException.FIELD_USERNAME, ValidationException.REASON_CANNOT_BE_EMPTY);    
       }
   }
   
   /**
    * 
    * @return encodedPassword
    */
   abstract public String getEncodedPassword();   
}