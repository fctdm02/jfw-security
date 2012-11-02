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

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;

import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public class SecurityRole extends DomainObject {

	/** */
	private static final long serialVersionUID = 1L;
	
	/** */
	public static final String MAPPING_DELIMITER = "-->";

	/** */
	private Long securityRoleId;

	/** */
	private String roleName;

	/** */
	private String displayName;
	
	/** */
	private String description;

    /** */
    private boolean assignByDefault;
		
	/** 
	 * Used to facilitate multi-tenancy.  Each domain object must belong to a multi-tenancy "realm".  If any unique constraints are
	 * created on 'name' fields, then those constraints need to incorporate the realm.  e.g. 'principalName' on the 'SecurityPrincipal' table
	 * should have a unique index created that is a combination of principalName and the multiTenancyRealm foreign key.
	 */
	private MultiTenancyRealm multiTenancyRealm;

	/**
	 * The set of security principals that are associated with this security role.
	 */
	private Set<SecurityPrincipal> memberSecurityPrincipals = new TreeSet<SecurityPrincipal>();	

    /**
     * The set of security roles that are "included" as part of this role (Role Hierarchy).
     */
    private Set<SecurityRole> includedSecurityRoles = new TreeSet<SecurityRole>(); 
	
	/**
	 * 
	 */
	public SecurityRole() {
	}

	/**
	 * @return the securityRoleId
	 */
	@XmlElement
	public final Long getSecurityRoleId() {
		return securityRoleId;
	}

	/**
	 * @param securityRoleId the securityRoleId to set
	 */
	public final void setSecurityRoleId(Long securityRoleId) {
		this.securityRoleId = securityRoleId;
	}

	/**
	 * @return the roleName
	 */
	@XmlElement
	public final String getRoleName() {
		return this.roleName;
	}

	/**
	 * @param roleName the roleName to set
	 */
	public final void setRoleName(String roleName) {
		this.roleName = DomainObject.trimString(roleName);
	}

	/**
	 * @return the displayName
	 */
	@XmlElement
	public final String getDisplayName() {
		return this.displayName;
	}

	/**
	 * @param displayName the displayName to set
	 */
	public final void setDisplayName(String displayName) {
		this.displayName = DomainObject.trimString(displayName);
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
	    this.description = DomainObject.setOptionalStringValue(description);
	}

    /**
     * 
     * @return
     */
    public final boolean getAssignByDefault() {
        return this.assignByDefault;
    }
    
    /**
     * 
     * @param assignByDefault
     */
    public final void setAssignByDefault(boolean assignByDefault) {
        this.assignByDefault = assignByDefault;
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
	
	/**
	 * @return the memberSecurityPrincipals
	 */
	public final Set<SecurityPrincipal> getMemberSecurityPrincipals() {
		return memberSecurityPrincipals;
	}

	/**
	 * @param memberSecurityPrincipals the memberSecurityPrincipals to set
	 */
	public final void setMemberSecurityPrincipals(Set<SecurityPrincipal> memberSecurityPrincipals) {
		this.memberSecurityPrincipals = memberSecurityPrincipals;
	}

	/**
	 * @param securityPrincipal the securityPrincipal to add
	 * @throws ObjectAlreadyExistsException
	 */
	public final void addMemberSecurityPrincipal(SecurityPrincipal securityPrincipal) throws ObjectAlreadyExistsException {
		if (securityPrincipal == null) {
			throw new ServiceException("Security Principal cannot be null.");
		}
		if (this.memberSecurityPrincipals.contains(securityPrincipal)) {
			throw new ObjectAlreadyExistsException("security principal: " 
				+ securityPrincipal 
				+ " has already been associated with security role: " 
				+ this);
		}
		this.memberSecurityPrincipals.add(securityPrincipal);
	}

	/**
	 * @param securityPrincipal the securityPrincipal to remove
	 */
	public final boolean removeMemberSecurityPrincipal(SecurityPrincipal securityPrincipal) {
		return this.memberSecurityPrincipals.remove(securityPrincipal);
	}

    /**
     * 
     * @return Set<String>
     */
    public final Set<String> getSecurityRoleMappings() {
        Set<String> securityRoleMappings = new TreeSet<String>();
        Iterator<SecurityPrincipal> iterator = this.memberSecurityPrincipals.iterator();
        while (iterator.hasNext()) {
            SecurityPrincipal securityPrincipal = iterator.next();
            securityRoleMappings.add(this.roleName + MAPPING_DELIMITER + securityPrincipal.getPrincipalName());
        }       
        return securityRoleMappings;
    }
	
    /**
     * @return the includedSecurityRoles
     */
    @XmlElementWrapper(name="includedSecurityRoles")
    @XmlElement(name="includedSecurityRole")
    public final Set<SecurityRole> getIncludedSecurityRoles() {
        return includedSecurityRoles;
    }

    /**
     * @param includedSecurityRoles the includedSecurityRoles to set
     */
    public final void setIncludedSecurityRoles(Set<SecurityRole> includedSecurityRoles) {
        this.includedSecurityRoles = includedSecurityRoles;
    }

    /**
     * @param securityRole the securityPrincipal to add
     * @throws ObjectAlreadyExistsException
     */
    public final void addIncludedSecurityRole(SecurityRole securityRole) throws ObjectAlreadyExistsException {
        if (securityRole == null) {
            throw new ServiceException("Security Role cannot be null.");
        }
        if (this.includedSecurityRoles.contains(securityRole)) {
            throw new ObjectAlreadyExistsException("security role: " 
                + securityRole 
                + " has already been associated with security role: " 
                + this);
        }
        this.includedSecurityRoles.add(securityRole);
    }

    /**
     * @param securityRole the securityPrincipal to remove
     */
    public final boolean removeIncludedSecurityRole(SecurityRole securityRole) {
        return this.includedSecurityRoles.remove(securityRole);
    }
	
	/**
	 * 
	 * @param principalName
	 * @return security Role Mappings For SecurityPrincipal
	 */
	public final Set<String> getSecurityRoleMappingsForSecurityPrincipal(String principalName) {
		Set<String> securityRoleMappings = new TreeSet<String>();
		Iterator<SecurityPrincipal> iterator = this.memberSecurityPrincipals.iterator();
		while (iterator.hasNext()) {
			SecurityPrincipal securityPrincipal = iterator.next();
			if (securityPrincipal.getPrincipalName().equalsIgnoreCase(principalName)) {
				securityRoleMappings.add(this.roleName + MAPPING_DELIMITER + securityPrincipal.getPrincipalName());	
			}
		}		
		return securityRoleMappings;
	}

	/*
	 * (non-Javadoc)
	 * @seecom.compuware.frameworks.security.service.api.model.DomainObject#getPersistentIdentity()
	 */
	public final Long getPersistentIdentity() {
		
		return getSecurityRoleId();
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getNaturalIdentity()
    */
   public final String getNaturalIdentity() {
	   return this.roleName;
   }
	   
	/*
	 * (non-Javadoc)
	 * @seecom.compuware.frameworks.security.service.api.model.DomainObject#validate()
	 */
	public final void validate() throws ValidationException {

	    if (this.multiTenancyRealm == null) {
	        throw new ValidationException(ValidationException.FIELD_MULTI_TENANCY_REALM, ValidationException.REASON_CANNOT_BE_NULL);
		}

        if (this.getDisplayName() == null || this.getDisplayName().isEmpty()) {
            throw new ValidationException(ValidationException.FIELD_ROLE_DISPLAY_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
        }	    
	    
		if (this.getRoleName() == null || this.getRoleName().isEmpty()) {
			throw new ValidationException(ValidationException.FIELD_ROLENAME, ValidationException.REASON_CANNOT_BE_EMPTY);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#toString()
	 */
	public final String toString() {
		
		return this.getDisplayName();
	}
}