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

import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public final class MultiTenancyRealm extends DomainObject {

	/** */
	private static final long serialVersionUID = 1L;

	
	/** */
	private Long multiTenancyRealmId;
	
	/** The unique name given for the realm. */
	private String realmName = IManagementService.DEFAULT_REALM_NAME; 

    /** */
    private String description = IManagementService.DEFAULT_REALM_DESCRIPTION;
      
    /** 
     * If "Customer LDAP" authentication mode, then this is used to construct URL and 
     * LDAP searches where each "realm" is assumed to be in a different partition. 
     */
    private String ldapBaseDn = IManagementService.DEFAULT_REALM_LDAP_BASE_DN;
    
	/** */
    private int minimumUsernameLength = IManagementService.DEFAULT_REALM_MINIMUM_USER_NAME_LENGTH;

    /** */
    private int minimumGroupnameLength = IManagementService.DEFAULT_REALM_MINIMUM_GROUP_NAME_LENGTH;
    
	/** */
    private int sessionMaximumLengthInMinutes = IManagementService.DEFAULT_REALM_SESSION_MAX_LENGTH_IN_MINUTES;
    
    /** */
    private int sessionTimeoutInMinutes = IManagementService.DEFAULT_REALM_SESSION_TIMEOUT_IN_MINUTES;

    /** */
    private boolean sessionAllowConcurrentLogin = IManagementService.DEFAULT_REALM_SESSION_ALLOW_CONCURRENT_LOGIN;
    
    /** */
    private String activePasswordPolicyName = IManagementService.DEFAULT_LOW_SECURITY_PASSWORD_POLICY_NAME;
    
    /** */
    private Set<PasswordPolicy> passwordPolicies = new TreeSet<PasswordPolicy>();
    
    /** */
    @XmlTransient
    private Set<SecurityPrincipal> securityPrincipals = new TreeSet<SecurityPrincipal>();

    /** */
    @XmlTransient
    private Set<SecurityRole> securityRoles = new TreeSet<SecurityRole>();

    /** */
    @XmlTransient
    private Set<AuditEvent> auditEvents = new TreeSet<AuditEvent>();    
    
   /**
    * 
    */
   public MultiTenancyRealm() {     
   }
   
	/**
    * @return the multiTenancyRealmId
    */
   @XmlAttribute
   public Long getMultiTenancyRealmId() {
      return multiTenancyRealmId;
   }

   /**
    * @param multiTenancyRealmId the multiTenancyRealmId to set
    */
   public void setMultiTenancyRealmId(Long multiTenancyRealmId) {
      this.multiTenancyRealmId = multiTenancyRealmId;
   }

   /**
    * @return the realmName
    */
   @XmlAttribute
   public String getRealmName() {
       return this.realmName;
   }

	/**
	 * @param realmName the realmName to set
	 */
	public void setRealmName(String realmName) {
	    this.realmName = DomainObject.trimString(realmName);
	}

   /**
    * @return the description
    */
   @XmlElement
   public String getDescription() {
       return DomainObject.getOptionalStringValue(this.description);
   }

   /**
    * @param description the description to set
    */
   public void setDescription(String description) {
       this.description = DomainObject.setOptionalStringValue(description);
   }
	
   /**
    * @return the ldapBaseDn
    */
   @XmlElement
   public String getLdapBaseDn() {
       return DomainObject.getOptionalStringValue(this.ldapBaseDn);
   }

   /**
    * @param ldapBaseDn the ldapBaseDn to set
    */
   public void setLdapBaseDn(String ldapBaseDn) {
       this.ldapBaseDn = DomainObject.setOptionalStringValue(ldapBaseDn);
   }  
   
   /**
	 * @return the minimumUsernameLength
	 */
   @XmlElement
	public int getMinimumUsernameLength() {
		return minimumUsernameLength;
	}

	/**
	 * @param minimumUsernameLength the minimumUsernameLength to set
	 */
	public void setMinimumUsernameLength(int minimumUsernameLength) {
		this.minimumUsernameLength = minimumUsernameLength;
	}

	/**
	 * @return the minimumGroupnameLength
	 */
	@XmlElement
	public int getMinimumGroupnameLength() {
		return minimumGroupnameLength;
	}

	/**
	 * @param minimumGroupnameLength the minimumGroupnameLength to set
	 */
	public void setMinimumGroupnameLength(int minimumGroupnameLength) {
		this.minimumGroupnameLength = minimumGroupnameLength;
	}   
   
    /**
	 * @return the sessionMaximumLengthInMinutes
	 */
	@XmlElement
	public int getSessionMaximumLengthInMinutes() {
		return sessionMaximumLengthInMinutes;
	}

	/**
	 * @param sessionMaximumLengthInMinutes the sessionMaximumLengthInMinutes to set
	 */
	public void setSessionMaximumLengthInMinutes(int sessionMaximumLengthInMinutes) {
		this.sessionMaximumLengthInMinutes = sessionMaximumLengthInMinutes;
	}

	/**
	 * @return the sessionTimeoutInMinutes
	 */
	@XmlElement
	public int getSessionTimeoutInMinutes() {
		return sessionTimeoutInMinutes;
	}

	/**
	 * @param sessionTimeoutInMinutes the sessionTimeoutInMinutes to set
	 */
	public void setSessionTimeoutInMinutes(int sessionTimeoutInMinutes) {
		this.sessionTimeoutInMinutes = sessionTimeoutInMinutes;
	}

	/**
	 * @return the sessionAllowConcurrentLogin
	 */
	@XmlElement
	public boolean isSessionAllowConcurrentLogin() {
		return sessionAllowConcurrentLogin;
	}

	/**
	 * @param sessionAllowConcurrentLogin the sessionAllowConcurrentLogin to set
	 */
	public void setSessionAllowConcurrentLogin(boolean sessionAllowConcurrentLogin) {
		this.sessionAllowConcurrentLogin = sessionAllowConcurrentLogin;
	}
	
	/**
     * @return the activePasswordPolicyName
     */
    public final String getActivePasswordPolicyName() {
        return this.activePasswordPolicyName;
    }

    /**
     * @param activePasswordPolicyName the activePasswordPolicyName to set
     */
    public final void setActivePasswordPolicyName(String activePasswordPolicyName) {
		this.activePasswordPolicyName = DomainObject.trimString(activePasswordPolicyName);
    }

    /**
	 * @return the passwordPolicies
	 */
	@XmlElementWrapper(name="passwordPolicySet")
    @XmlElement(name="passwordPolicy")
	public Set<PasswordPolicy> getPasswordPolicies() {
		return passwordPolicies;
	}

    /**
     * @param passwordPolicies the passwordPolicies to set
     */
    public void setPasswordPolicies(Set<PasswordPolicy> passwordPolicies) {
        this.passwordPolicies = passwordPolicies;
    }

    /**
     * 
     * @param passwordPolicy
     */
    public void addPasswordPolicy(PasswordPolicy passwordPolicy) {
        passwordPolicy.setMultiTenancyRealm(this);
        this.passwordPolicies.add(passwordPolicy);
    }
	
    /**
     * 
     * @param passwordPolicyName
     * @throws ObjectNotFoundException
     * @return PasswordPolicy
     */
    public PasswordPolicy removePasswordPolicy(String passwordPolicyName) throws ObjectNotFoundException {
        
        PasswordPolicy passwordPolicyToRemove = null;
        Iterator<PasswordPolicy> iterator = this.passwordPolicies.iterator();
        while (iterator.hasNext()) {
            
            PasswordPolicy passwordPolicy = iterator.next();
            if (passwordPolicy.getName().equalsIgnoreCase(passwordPolicyName)) {
                passwordPolicyToRemove = passwordPolicy;
            }
        }
        
        if (passwordPolicyToRemove == null) {
            throw new ObjectNotFoundException("Could not find password policy with name: [" + passwordPolicyName + "] in realm: [" + this.getRealmName() + "].");
        }
        
        if (passwordPolicyName.equalsIgnoreCase(this.activePasswordPolicyName)) {
            throw new IllegalStateException("Cannot remove the active password policy: [" + passwordPolicyName + "] in realm: [" + this.getRealmName() + "].");
        }
        
        this.passwordPolicies.remove(passwordPolicyToRemove);
        
        return passwordPolicyToRemove;
    }
    
	/**
	 * 
	 * @return
	 */
	public PasswordPolicy getActivePasswordPolicy() {

        Iterator<PasswordPolicy> iterator = passwordPolicies.iterator();
        while (iterator.hasNext()) {
            
            PasswordPolicy passwordPolicy = iterator.next();
            if (passwordPolicy.getName().equalsIgnoreCase(this.activePasswordPolicyName)) {
                return passwordPolicy;
            }
        }
        throw new IllegalStateException("No active password policy exists for realm: " + this.getRealmName());
	}
	
	/**
	 * 
	 * @param passwordPolicyName
	 * @return The password policy with the given name
	 * @throws ObjectNotFoundException
	 */
	public PasswordPolicy getPasswordPolicyByPasswordPolicyName(String passwordPolicyName) throws ObjectNotFoundException {
	    
	    Iterator<PasswordPolicy> iterator = passwordPolicies.iterator();
	    while (iterator.hasNext()) {
	        
	        PasswordPolicy passwordPolicy = iterator.next();
	        if (passwordPolicy.getName().equalsIgnoreCase(passwordPolicyName)) {
	            return passwordPolicy;
	        }
	    }
	    throw new ObjectNotFoundException("Could not find password policy with name: " + passwordPolicyName + " for realm: " + this.getRealmName());
	}

    /**
     * 
     * @param passwordPolicyName
     * @throws ObjectNotFoundException
     */
    public void setActivePasswordPolicy(String passwordPolicyName) throws ObjectNotFoundException {
        
        Iterator<PasswordPolicy> iterator = passwordPolicies.iterator();
        boolean foundPasswordPolicy = false;
        while (iterator.hasNext()) {
            
            PasswordPolicy passwordPolicy = iterator.next();
            if (passwordPolicy.getName().equalsIgnoreCase(passwordPolicyName)) {
                foundPasswordPolicy = true;
                this.activePasswordPolicyName = passwordPolicyName;
            }
        }
        if (!foundPasswordPolicy) {
            throw new ObjectNotFoundException("Could not find password policy with name: " + passwordPolicyName + " for realm: " + this.getRealmName());
        }
    }
	
	/**
	 * @return the securityPrincipals
	 */
	@XmlTransient
	public Set<SecurityPrincipal> getSecurityPrincipals() {
		return securityPrincipals;
	}

	/**
	 * @param securityPrincipals the securityPrincipals to set
	 */
	public void setSecurityPrincipals(Set<SecurityPrincipal> securityPrincipals) {
		this.securityPrincipals.addAll(securityPrincipals);
	}
	
	/**
	 * 
	 * @param securityPrincipal
	 */
	public void addSecurityPrincipal(SecurityPrincipal securityPrincipal) {
		this.securityPrincipals.add(securityPrincipal);
	}

	/**
	 * 
	 * @param securityPrincipal
	 */
	public boolean removeSecurityPrincipal(SecurityPrincipal securityPrincipal) {
		return this.securityPrincipals.remove(securityPrincipal);
	}
	
	/**
	 * @return the securityRoles
	 */
	@XmlTransient
	public Set<SecurityRole> getSecurityRoles() {
		return securityRoles;
	}

	/**
	 * @param securityRoles the securityRoles to set
	 */
	public void setSecurityRoles(Set<SecurityRole> securityRoles) {
		this.securityRoles.addAll(securityRoles);
	}
	
	/**
	 * 
	 * @param securityRole
	 */
	public void addSecurityRole(SecurityRole securityRole) {
		this.securityRoles.add(securityRole);
	}

	/**
	 * 
	 * @param securityRole
	 */
	public boolean removeSecurityRole(SecurityRole securityRole) {
		return this.securityRoles.remove(securityRole);
	}

	/**
	 * @return the auditEvents
	 */
	@XmlTransient
	public Set<AuditEvent> getAuditEvents() {
		return auditEvents;
	}

	/**
	 * @param auditEvents the auditEvents to set
	 */
	public void setAuditEvents(Set<AuditEvent> auditEvents) {
		this.auditEvents.addAll(auditEvents);
	}
	
	/**
	 * 
	 * @param auditEvent
	 */
	public void addAuditEvent(AuditEvent auditEvent) {
		this.auditEvents.add(auditEvent);
	}

	/**
	 * 
	 * @param auditEvent
	 */
	public boolean removeAuditEvent(AuditEvent auditEvent) {
		return this.auditEvents.remove(auditEvent);
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#getPersistentIdentity()
	 */
	public Long getPersistentIdentity() {
		
	   return multiTenancyRealmId;
	}

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getNaturalIdentity()
    */
   public String getNaturalIdentity() {
	   
	   return realmName;
   }
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
	 */
	public void validate() throws ValidationException {
		
		if (this.realmName == null || this.realmName.isEmpty()) {
			throw new ValidationException(ValidationException.FIELD_REALM_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
		}
				
		if (this.activePasswordPolicyName == null) {
		    throw new ValidationException(ValidationException.FIELD_ACTIVE_PASSWORD_POLICY_NAME, ValidationException.REASON_CANNOT_BE_NULL);
		}
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#toString()
    */
   public String toString() {
	   
      return realmName;      
   }
}