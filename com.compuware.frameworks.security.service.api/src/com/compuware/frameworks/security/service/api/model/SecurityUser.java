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

import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;

import com.compuware.frameworks.security.service.api.authentication.IAuthenticatingUser;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public class SecurityUser extends AbstractUser implements IAuthenticatingUser {

	/** */
	private static final long serialVersionUID = 1L;
	
	/** */
	private String firstName;
	
	/** */
	private String lastName;
	
	/** */
	private String primaryEmailAddress;
	
	/** */
	private int numberUnsucccessfulLoginAttempts;
	
	/** 
	 * Whether or not the user is allowed to log in.  This may occur via the password 
	 * policy if a user has tried to login more than than the max. number of unsuccessful 
	 * login attempts.  
	 */
	private boolean isAccountLocked = false;
		
	/** 
	 * Per the password policy, a certain number of passwords are kept so that the user
	 * is prevented from re-using old passwords too soon. These passwords should only be
	 * retrieved/set for authentication requests (even though they will be encoded).
	 */
	private Set<Password> passwords = new TreeSet<Password>();
	
	/**
	 * 
	 */
	public SecurityUser() {		
	}

	/**
	 * @return the firstName
	 */
	@XmlAttribute
	public String getFirstName() {
		return this.firstName;
	}

	/**
	 * @param firstName the firstName to set
	 */
	public final void setFirstName(String firstName) {
		this.firstName = DomainObject.trimString(firstName);
	}

	/**
	 * @return the lastName
	 */
	@XmlAttribute
	public final String getLastName() {
		return this.lastName;
	}

	/**
	 * @param lastName the lastName to set
	 */
	public final void setLastName(String lastName) {
		this.lastName = DomainObject.trimString(lastName);
	}

	/**
	 * @return the primaryEmailAddress
	 */
	@XmlAttribute
	public final String getPrimaryEmailAddress() {
	    return DomainObject.getOptionalStringValue(this.primaryEmailAddress);
	}

	/**
	 * @param primaryEmailAddress the primaryEmailAddress to set
	 */
	public final void setPrimaryEmailAddress(String primaryEmailAddress) {
	    this.primaryEmailAddress = DomainObject.setOptionalStringValue(primaryEmailAddress);
	}
	
	/**
	 * @return the numberUnsucccessfulLoginAttempts
	 */
	@XmlAttribute
	public final int getNumberUnsucccessfulLoginAttempts() {
		return numberUnsucccessfulLoginAttempts;
	}

	/**
	 * @param numberUnsucccessfulLoginAttempts the numberUnsucccessfulLoginAttempts to set
	 */
	public final void setNumberUnsucccessfulLoginAttempts(int numberUnsucccessfulLoginAttempts) {
		this.numberUnsucccessfulLoginAttempts = numberUnsucccessfulLoginAttempts;
	}

	/**
	 * 
	 */
    public final void incrementNumberUnsucccessfulLoginAttempts() {
        this.numberUnsucccessfulLoginAttempts = this.numberUnsucccessfulLoginAttempts + 1;
    }
	
	/**
	 * @return the isAccountLocked
	 */
	@XmlAttribute
	public final boolean getIsAccountLocked() {
		return isAccountLocked;
	}

	/**
	 * @param isAccountLocked the isAccountLocked to set
	 */
	public final void setIsAccountLocked(boolean isAccountLocked) {
		this.isAccountLocked = isAccountLocked;
	}

	/**
	 * @return <code>true</code> if the account is active; <code>false</code> otherwise.
	 */
	public final boolean getIsAccountActive() {
		return !isAccountLocked;
	}
	
	/**
	 * Convenience method for <code>setIsAccountLocked(true)</code>
	 */
	public final void deactivateAccount() {
		this.setIsAccountLocked(true);
	}

	/**
	 * Convenience method for <code>setIsAccountLocked(false)</code>
	 */
	public final void activateAccount() {
		this.setIsAccountLocked(false);
	}
	
	/**
	 * @return the passwords
	 */
	@XmlElementWrapper(name="passwordSet")
	@XmlElement(name="password")
	public final Set<Password> getPasswords() {
		return passwords;
	}

	/**
	 * @param passwords the passwords to set
	 */
	public final void setPasswords(Set<Password> passwords) {		
		this.passwords = passwords;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.AbstractUser#getEncodedPassword()
	 */
	public final String getEncodedPassword() {
		return this.getPassword();
	}	

	/**
	 * 
	 * @return password
	 */
    public final String getPassword() {
    	Password[] passwordArray = this.passwords.toArray(new Password[this.passwords.size()]);
    	return passwordArray[0].getEncodedPassword();
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isAccountNonExpired()
     */
    public final boolean isAccountNonExpired() {
    	return !this.isPasswordExpired();    	
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isAccountNonLocked()
     */
    public final boolean isAccountNonLocked() {
    	return !this.getIsAccountLocked();
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isCredentialsNonExpired()
     */
    public final boolean isCredentialsNonExpired() {
    	return !this.isPasswordExpired();
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.security.core.userdetails.UserDetails#isEnabled()
     */
    public final boolean isEnabled() {
    	return !this.getIsAccountLocked();
    }
    
	/**
	 * 
	 * @param password
	 */
	public final void addPassword(Password password) {
		password.setSecurityUser(this);
		
        // Since the password's equality is based upon creation date, we may need to tweak the creation date by a second in order
        // to guarantee uniqueness.
        if (this.passwords.contains(password)) {
            password.setCreationDate(System.currentTimeMillis() + 1000);
        }
		
		this.passwords.add(password);
	}
	
	/**
	 * 
	 * @return current password
	 */
	public final Password getCurrentPassword() {
	    
		// Return the "newest" password, which is the one with the most recent 'creationDate'
	    // (in other words, the one with the greatest value)
	    Password currentPassword = null;
	    Iterator<Password> iterator = this.passwords.iterator();
	    while (iterator.hasNext()) {
	        Password password = iterator.next();
	        if (currentPassword == null || password.getCreationDate() >= currentPassword.getCreationDate()) {
	            currentPassword = password;
	        }
	    }
	    return currentPassword;
	}
	
	/**
	 * If the password policy has an age limit of -1, 
	 * then the user password will not expire due to age.  
	 * However, the password can be explicitly marked as expired. 
	 * 
	 * @return is password expired
	 */
	public final boolean isPasswordExpired() {
		
		boolean isPasswordExpired = false;
		MultiTenancyRealm multiTenancyRealm = getMultiTenancyRealm(); 
		PasswordPolicy passwordPolicy = multiTenancyRealm.getActivePasswordPolicy();
		Password password = getCurrentPassword();
		if (password.getIsPasswordExpired()) {
			isPasswordExpired = true;
		} else {
			int ageLimit = passwordPolicy.getAgeLimit();
			int passwordAge = password.getAgeInDays();
			if (ageLimit != -1 && passwordAge > ageLimit) {
				isPasswordExpired = true;
			}
		}
		return isPasswordExpired;
	}

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
     */
    public final void validate() throws ValidationException {
        boolean validatePasswords = true;
        validate(validatePasswords);
    }
	
    /**
     * 
     * @param validatePasswords
     * @throws ValidationException
     */
    public final void validate(boolean validatePasswords) throws ValidationException {
        super.validate();
        
        if (this.getUsername().length() < this.getMultiTenancyRealm().getMinimumUsernameLength()) {
            
            String reason = ValidationException.REASON_MINIMUM_LENGTH_NOT_SATISFIED;
            reason = reason.replace(ValidationException.TOKEN_ZERO, Integer.toString(this.getMultiTenancyRealm().getMinimumUsernameLength()));
            throw new ValidationException(ValidationException.FIELD_USERNAME, reason);
        }
        
        if (this.firstName == null || this.firstName.isEmpty()) {
            throw new ValidationException(ValidationException.FIELD_FIRST_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
        }

        if (this.lastName == null || this.lastName.isEmpty()) {
            throw new ValidationException(ValidationException.FIELD_LAST_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
        }
        
        if (validatePasswords) {
            if (this.passwords == null || this.passwords.isEmpty()) {
                throw new ValidationException(ValidationException.FIELD_PASSWORD, ValidationException.REASON_NO_PASSWORD_SPECIFIED);
            }        
            
            Iterator<Password> iterator = this.passwords.iterator();
            while (iterator.hasNext()) {
                
                Password password = iterator.next();
                if (password.getSecurityUser() == null) {
                    throw new ValidationException(ValidationException.FIELD_OWNING_SECURITY_USER, ValidationException.REASON_CANNOT_BE_NULL);
                }
                
                if (password.getSecurityUser() != this) {
                    String reason = ValidationException.REASON__TOKEN__DOES_NOT_MATCH__TOKEN__;
                    reason = reason.replace(ValidationException.TOKEN_ZERO, password.getSecurityUser().toString());
                    reason = reason.replace(ValidationException.TOKEN_ONE, this.toString());
                    throw new ValidationException(ValidationException.FIELD_OWNING_SECURITY_USER, reason);
                }
            }
        }
    }
}