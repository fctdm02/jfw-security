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

import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement(name="password")
public final class Password extends DomainObject {

	/** */
	private static final long serialVersionUID = 1L;

	/** */
	private Long passwordId;
	
    /** */
	private String encodedPassword;
	
	/** */
	private boolean isPasswordExpired = false;
	
	/** */
	private Long creationDate;

	/** The owning SecurityUser **/
	private SecurityUser securityUser; 
	
	/**
	 * 
	 */
	public Password() {		
	}
	
    /**
     * This method is used by JAXB to re-associate a parent back to a child.  
     * This works in conjunction with the @XmlTransient annotation defined here in the child.
     * 
     * @param unmarshaller
     * @param parent
     */
	public void afterUnmarshal(Unmarshaller unmarshaller, Object owningUser) {
		if ((owningUser != null) && !(owningUser instanceof SecurityUser)) {
			return;
		}
		securityUser = (SecurityUser)owningUser;
	}

   /**
    * @return the passwordId
    */
   @XmlAttribute
   public Long getPasswordId() {
      return passwordId;
   }

   /**
    * @param passwordId the passwordId to set
    */
   public void setPasswordId(Long passwordId) {
      this.passwordId = passwordId;
   }
	
	/**
	 * @return the encodedPassword
	 */
    @XmlElement
	public String getEncodedPassword() {
		return this.encodedPassword;
	}

	/**
	 * @param encodedPassword the encodedPassword to set
	 */
	public void setEncodedPassword(String encodedPassword) {
		if (encodedPassword == null || encodedPassword.length() == 0) {
			this.encodedPassword = DomainObject.ORACLE_EMPTY_STRING_ID;
		} else {
			this.encodedPassword = encodedPassword;
		}
	}
	
	/**
	 * @return the isPasswordExpired
	 */
	@XmlAttribute
	public boolean getIsPasswordExpired() {
		return isPasswordExpired;
	}

	/**
	 * @param isPasswordExpired the isPasswordExpired to set
	 */
	public void setIsPasswordExpired(boolean isPasswordExpired) {
		this.isPasswordExpired = isPasswordExpired;
	}
	
	/**
	 * @return the creationDate
	 */
    @XmlElement
	public Long getCreationDate() {
		return creationDate;
	}

	/**
	 * @param creationDate the creationDate to set
	 */
	public void setCreationDate(Long creationDate) {
		this.creationDate = creationDate;
	}

	/**
	 * @return the securityUser
	 */
	@XmlTransient
	public SecurityUser getSecurityUser() {
		return securityUser;
	}

	/**
	 * @param securityUser the securityUser to set
	 */
	public void setSecurityUser(SecurityUser securityUser) {
		this.securityUser = securityUser;
	}
	
	/**
	 * 
	 * @return The number of days, from the current system time, when the 
	 * password was created. 
	 */
	public int getAgeInDays() {
		long currentTime = System.currentTimeMillis();
		long ageInMillis = currentTime - creationDate.longValue();
		return (int)(ageInMillis / (1000 * 60 * 60 * 24));
	}

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getPersistentIdentity()
    */
   public Long getPersistentIdentity() {
      return getPasswordId();
   }
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getNaturalIdentity()
    */
   public String getNaturalIdentity() {
       return this.creationDate.toString();
   }

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
	 */
	public void validate() throws ValidationException {
	    
		if (this.getCreationDate() == null) {
			throw new ValidationException(ValidationException.FIELD_CREATION_DATE, ValidationException.REASON_CANNOT_BE_EMPTY);
		}
		
		if (this.getEncodedPassword() == null) {
		    throw new ValidationException(ValidationException.FIELD_ENCODED_PASSWORD, ValidationException.REASON_CANNOT_BE_EMPTY);
		}
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#toString()
    */
   public String toString() {
      return this.encodedPassword;
   }
}
