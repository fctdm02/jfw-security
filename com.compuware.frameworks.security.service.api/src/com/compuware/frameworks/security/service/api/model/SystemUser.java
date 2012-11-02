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

import com.compuware.frameworks.security.service.api.authentication.IAuthenticatingUser;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public final class SystemUser extends AbstractUser implements IAuthenticatingUser {

	/** */
	private static final long serialVersionUID = 1L;

	
	/** */
	private String encodedPassword;

	/**
	 * 
	 */
	public SystemUser() {
	}

	/*
	 * (non-Javadoc)
	 */
	@XmlElement
	public String getEncodedPassword() {
		return encodedPassword;
	}

	/**
	 * 
	 * 
	 * @param encodedPassword the encodedPassword to set
	 */
	public void setEncodedPassword(String encodedPassword) {
		this.encodedPassword = encodedPassword;
	}
		
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#getPassword()
     */
    public String getPassword() {
    	return this.getEncodedPassword();
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isAccountNonExpired()
     */
    public boolean isAccountNonExpired() {
    	return true;
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isAccountNonLocked()
     */
    public boolean isAccountNonLocked() {
    	return true;
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isCredentialsNonExpired()
     */
    public boolean isCredentialsNonExpired() {
    	return true;
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isEnabled()
     */
    public boolean isEnabled() {
    	return true;
    }
		
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
     */
    public void validate() throws ValidationException {
        super.validate();
                
        if (this.getEncodedPassword() == null || 
        		this.getEncodedPassword().isEmpty() || 
        		this.getEncodedPassword().equals(DomainObject.ORACLE_EMPTY_STRING_ID)) {
            throw new ValidationException(ValidationException.FIELD_ENCODED_PASSWORD, ValidationException.REASON_CANNOT_BE_EMPTY);
        }
    }
}