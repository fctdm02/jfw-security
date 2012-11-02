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

import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import com.compuware.frameworks.security.service.api.model.exception.PasswordPolicyException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement(name="passwordPolicy")
public class PasswordPolicy extends DomainObject {
	
	/** */
	private static final long serialVersionUID = 1L;
	
	
   /** */
   private Long passwordPolicyId;
   
   /** */
   private String name; 

   /** */
   private String description;
	
   /** */
   private int ageLimit;
   
   /** */
   private int historyLimit;
   
   /** */
   private int minNumberOfDigits;
   
   /** */
   private int minNumberOfChars;
   
   /** */
   private int minNumberOfSpecialChars;
   
   /** */
   private int minPasswordLength;
   
   /** */
   private int maxNumberUnsuccessfulLoginAttempts;
   
	/** 
	 * Used to facilitate multi-tenancy.  Each domain object must belong to a multi-tenancy "realm".  If any unique constraints are
	 * created on 'name' fields, then those constraints need to incorporate the realm.  e.g. 'principalName' on the 'SecurityPrincipal' table
	 * should have a unique index created that is a combination of principalName and the multiTenancyRealm foreign key.
	 */
	private MultiTenancyRealm multiTenancyRealm;
   
   
   /**
    * 
    */
   public PasswordPolicy() {
   }
	
	/**
    * @return the passwordPolicyId
    */
   @XmlAttribute
   public final Long getPasswordPolicyId() {
      return passwordPolicyId;
   }

   /**
    * @param passwordPolicyId the passwordPolicyId to set
    */
   public final void setPasswordPolicyId(Long passwordPolicyId) {
      this.passwordPolicyId = passwordPolicyId;
   }

	/**
	 * @return the multiTenancyRealm
	 */
   @XmlTransient
	public final MultiTenancyRealm getMultiTenancyRealm() {
		return multiTenancyRealm;
	}

	/**
	 * @param multiTenancyRealm the multiTenancyRealm to set
	 */
	public final void setMultiTenancyRealm(MultiTenancyRealm multiTenancyRealm) {
		this.multiTenancyRealm = multiTenancyRealm;
	}
   
   /**
    * @return the name
    */
   @XmlAttribute
   public final String getName() {
       return this.name;
   }

   /**
    * @param name the name to set
    */
   public final void setName(String name) {
       this.name = DomainObject.trimString(name);
   }

   /**
    * @return the description
    */
   @XmlElement
   public final String getDescription() {
       return DomainObject.getOptionalStringValue(this.description);
   }

   /**
    * @param description the description to set
    */
   public final void setDescription(String description) {
       this.description = DomainObject.setOptionalStringValue(description);
   }
	
	/**
	 * An ageLimit value of either 0 or -1 means that there is no limit for a passwords age.<br>
	 * 
	 * @return the ageLimit for passwords (in days)
	 */
	@XmlElement
	public final int getAgeLimit() {
	    if (this.ageLimit < 14) {
	        this.ageLimit = -1;
	    }
		return this.ageLimit;
	}

	/**
     * An ageLimit value of either 0 or -1 means that there is no limit for a passwords age.<br>
     * Otherwise, the value must be between 14 and 365. 
	 * 
	 * @param ageLimit the password ageLimit to set (in days)
	 */
	public final void setAgeLimit(int ageLimit) {
        if (ageLimit == 0 || ageLimit == -1) {
            this.ageLimit = -1;
        } else if (ageLimit >= 14 && ageLimit <= 365) {
            this.ageLimit = ageLimit;    
        } else {
            throw new IllegalArgumentException("ageLimit (in days) must either be 0 or -1 (to disable) or be between 14 and 365, inclusive, but was: " + ageLimit);    
        }
	}

	/**
	 * A historyLimit value of either 0 or -1 means that there is no enforcing of password uniqueness between password changes.
	 * 
	 * @return the historyLimit for passwords (number of unique passwords that must be used before repeating)
	 */
	@XmlElement
	public final int getHistoryLimit() {
        if (this.historyLimit < 2) {
            this.historyLimit = -1;
        }
		return historyLimit;
	}

	/**
	 * A historyLimit value of either 0 or -1 means that there is no enforcing of password uniqueness between password changes.<br>
	 * Otherwise, the value must be between 2 and 60. 
	 * 
	 * @param historyLimit the historyLimit to set
	 */
	public final void setHistoryLimit(int historyLimit) {
        if (historyLimit == 0 || historyLimit == -1) {
            this.historyLimit = -1;
        } else if (historyLimit >= 2 && historyLimit <= 60) {
            this.historyLimit = historyLimit;    
        } else {
            throw new IllegalArgumentException("historyLimit must either be 0 or -1 (to disable) or be between 2 and 60, inclusive, but was: " + historyLimit);
        }
	}

	/**
	 * @return the minNumberOfDigits
	 */
	@XmlElement
	public final int getMinNumberOfDigits() {
		return minNumberOfDigits;
	}

	/**
	 * Must be between 0 and 127, inclusive.
	 * 
	 * @param minNumberOfDigits the minNumberOfDigits to set
	 */
	public final void setMinNumberOfDigits(int minNumberOfDigits) {
		if (minNumberOfDigits < 0 || minNumberOfDigits > 127) {
			throw new IllegalArgumentException("minNumberOfDigits must be between 0 and 127, inclusive, but was: " + minNumberOfDigits);
		}
		this.minNumberOfDigits = minNumberOfDigits;
	}

	/**
	 * @return the minNumberOfChars
	 */
	@XmlElement
	public final int getMinNumberOfChars() {
		return minNumberOfChars;
	}

	/**
	 * Must be between 0 and 127, inclusive.
	 * 
	 * @param minNumberOfChars the minNumberOfChars to set
	 */
	public final void setMinNumberOfChars(int minNumberOfChars) {
		if (minNumberOfChars < 0 || minNumberOfChars > 127) {
			throw new IllegalArgumentException("minNumberOfChars must be between 0 and 127, inclusive, but was: " + minNumberOfChars);
		}
		this.minNumberOfChars = minNumberOfChars;
	}

	/**
	 * @return the minNumberOfSpecialChars
	 */
	@XmlElement
	public final int getMinNumberOfSpecialChars() {
		return minNumberOfSpecialChars;
	}

	/**
	 * Must be between 0 and 127, inclusive.
	 * 
	 * @param minNumberOfSpecialChars the minNumberOfSpecialChars to set
	 */
	public final void setMinNumberOfSpecialChars(int minNumberOfSpecialChars) {
		if (minNumberOfSpecialChars < 0 || minNumberOfSpecialChars > 127) {
			throw new IllegalArgumentException("minNumberOfSpecialChars must be between 0 and 127, inclusive, but was: " + minNumberOfSpecialChars);
		}
		this.minNumberOfSpecialChars = minNumberOfSpecialChars;
	}

	/**
	 * @return the minPasswordLength
	 */
	@XmlElement
	public final int getMinPasswordLength() {
		return minPasswordLength;
	}

	/**
	 * Must be between 0 and 127, inclusive.
	 * 
	 * @param minPasswordLength the minPasswordLength to set
	 */
	public final void setMinPasswordLength(int minPasswordLength) {
		if (minPasswordLength < 0 || minPasswordLength > 127) {
			throw new IllegalArgumentException("minPasswordLength must be between 0 and 127, inclusive, but was: " + minPasswordLength);
		}
		this.minPasswordLength = minPasswordLength;
	}
	
    /**
     * A maxNumberUnsuccessfulLoginAttempts value of either 0 or -1 means that there is no limit for invalid login attempts.<br>
     * 
     * @return the maxNumberUnsuccessfulLoginAttempts
     */
	@XmlElement
	public final int getMaxNumberUnsuccessfulLoginAttempts() {
	    if (this.maxNumberUnsuccessfulLoginAttempts < 3) {
	        return -1;
	    }
		return maxNumberUnsuccessfulLoginAttempts;
	}

	/**
	 * A maxNumberUnsuccessfulLoginAttempts value of either 0 or -1 means that there is no limit to invalid login attempts.<br>
	 * Otherwise, the value must be between 3 and 127, inclusive. 
	 * 
	 * @param maxNumberUnsuccessfulLoginAttempts the maxNumberUnsuccessfulLoginAttempts to set
	 */
	public final void setMaxNumberUnsuccessfulLoginAttempts(int maxNumberUnsuccessfulLoginAttempts) {
	    if (maxNumberUnsuccessfulLoginAttempts == 0 || maxNumberUnsuccessfulLoginAttempts == -1) {
	        this.maxNumberUnsuccessfulLoginAttempts = -1;
	    } else if (maxNumberUnsuccessfulLoginAttempts >= 3 && maxNumberUnsuccessfulLoginAttempts <= 127) {
	        this.maxNumberUnsuccessfulLoginAttempts = maxNumberUnsuccessfulLoginAttempts;    
        } else {
            throw new IllegalArgumentException("maxNumberUnsuccessfulLoginAttempts must either be 0 or -1 (to disable) or be between 3 and 127, inclusive, but was: " + maxNumberUnsuccessfulLoginAttempts);
        }
	}
	
	/**
	 * 
	 * @param newClearTextPassword
	 * @param password
	 * @param securityUser
	 * @throws ValidationException
	 * @throws PasswordPolicyException
	 */
	public final void validateSecurityUserPasswordForPasswordPolicy(
	    String newClearTextPassword, 
	    Password password,
	    SecurityUser securityUser) 
	throws 
	    ValidationException, 
	    PasswordPolicyException {
							
		// Check to make sure the password has the minimum length.
		int length = newClearTextPassword.length();
		if (length < this.minPasswordLength) {
			throw new PasswordPolicyException("Invalid password length: " + length, PasswordPolicyException.MIN_PASSWORD_LENGTH_NOT_MET);
		}				
		
		// Check to make sure the password has the minimum number of characters.
		int charCount = 0;
		for (int i=0; i < length; i++) {
			char ch = newClearTextPassword.charAt(i);
			if (Character.isLetter(ch)) {
				charCount = charCount + 1;
			}
		}
		if (charCount < this.minNumberOfChars) {
			throw new PasswordPolicyException("Invalid character count: " + charCount, PasswordPolicyException.MIN_NUMBER_CHARS_NOT_MET);
		}		
				
		// Check to make sure the password has the minimum number of digits.
		int digitCount = 0;
		for (int i=0; i < length; i++) {
			char ch = newClearTextPassword.charAt(i);
			if (Character.isDigit(ch)) {
				digitCount = digitCount + 1;
			}
		}
		if (digitCount < this.minNumberOfDigits) {
			throw new PasswordPolicyException("Invalid digit count: " + digitCount, PasswordPolicyException.MIN_NUMBER_DIGITS_NOT_MET);
		}		
						
		// Check to make sure the password has the minimum number of special characters.
		int specialCharCount = 0;
		for (int i=0; i < length; i++) {
			char ch = newClearTextPassword.charAt(i);
			if (!Character.isDigit(ch) && !Character.isLetter(ch)) {
				specialCharCount = specialCharCount + 1;
			}
		}
		if (specialCharCount < this.minNumberOfSpecialChars) {
			throw new PasswordPolicyException("Invalid special character count: " + specialCharCount, PasswordPolicyException.MIN_NUMBER_SPECIAL_CHARS_NOT_MET);
		}
		
        if (this.historyLimit > 0) {
            
            Iterator<Password> passwordIterator = securityUser.getPasswords().iterator();
            int passwordIndex = 0;
            while (passwordIterator.hasNext() && passwordIndex <= this.historyLimit) {
                
                passwordIndex = passwordIndex + 1;
                if (passwordIterator.next().getEncodedPassword().equals(password.getEncodedPassword())) {
                    throw new PasswordPolicyException(PasswordPolicyException.PASSWORD_HISTORY_NOT_MET);
                }
            }
        }
		
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getPersistentIdentity()
    */
   public final Long getPersistentIdentity() {
	   
      return getPasswordPolicyId();
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getNaturalIdentity()
    */
   public final String getNaturalIdentity() {
	   return this.name;
   }
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
	 */
	public final void validate() throws ValidationException {

	    if (this.multiTenancyRealm == null) {
	        throw new ValidationException(ValidationException.FIELD_MULTI_TENANCY_REALM, ValidationException.REASON_CANNOT_BE_NULL);
		}
		
		if (this.getName() == null || this.getName().isEmpty()) {
		    throw new ValidationException(ValidationException.FIELD_PASSWORD_POLICY_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
		}
	}

	/**
	 * This method is used by JAXB to re-associate a parent back to a child.  
	 * This works in conjunction with the @XmlTransient annotation defined here in the child.
	 * 
	 * @param unmarshaller
	 * @param parent
	 */
	public final void afterUnmarshal(Unmarshaller unmarshaller, Object parent) {
		if ((parent != null) && !(parent instanceof MultiTenancyRealm)) {
			return;
		}
		this.multiTenancyRealm = (MultiTenancyRealm)parent;
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#toString()
    */
   public final String toString() {
      return this.name;      
   }
}
