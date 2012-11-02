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

import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.model.exception.PasswordPolicyException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
public class DomainObjectFactory {
			    
    /**
     * 
     * @return MultiTenancyRealm
     * @throws ValidationException
     */
    public final MultiTenancyRealm createDefaultMultiTenancyRealm() throws ValidationException {
        
        boolean isDeletable = false;
        boolean isModifiable = true;
        
        MultiTenancyRealm multiTenancyRealm = new DomainObjectFactory().createMultiTenancyRealm(
            IManagementService.DEFAULT_REALM_NAME,
            IManagementService.DEFAULT_REALM_DESCRIPTION, 
            IManagementService.DEFAULT_REALM_LDAP_BASE_DN, 
            new TreeSet<PasswordPolicy>(),
            isDeletable,
            isModifiable);
        
        multiTenancyRealm.setActivePasswordPolicyName(IManagementService.DEFAULT_REALM_ACTIVE_PASSWORD_POLICY_NAME);
        
        return multiTenancyRealm;
    }
    
	/**
	 * @param realmName
	 * @param description
	 * @param ldapBaseDn
	 * @param passwordPolicies
	 * @param isDeletable
	 * @param isModifiable
	 * @return MultiTenancyRealm
	 * @throws ValidationException 
	 */
	public final MultiTenancyRealm createMultiTenancyRealm(
		String realmName,
		String description,
		String ldapBaseDn,
		Set<PasswordPolicy> passwordPolicies,
        boolean isDeletable,
        boolean isModifiable) throws ValidationException {
		
		MultiTenancyRealm multiTenancyRealm = new MultiTenancyRealm();
		
		multiTenancyRealm.setRealmName(realmName);
		multiTenancyRealm.setDescription(description);
		multiTenancyRealm.setLdapBaseDn(ldapBaseDn);
		multiTenancyRealm.setIsDeletable(isDeletable);
		multiTenancyRealm.setIsModifiable(isModifiable);
				
		Iterator<PasswordPolicy> iterator = passwordPolicies.iterator();
		while (iterator.hasNext()) {
			
			PasswordPolicy passwordPolicy = iterator.next();
			passwordPolicy.setMultiTenancyRealm(multiTenancyRealm);
			multiTenancyRealm.getPasswordPolicies().add(passwordPolicy);
		}
		
		return multiTenancyRealm;
	}

    /**
     * 
     * @param passwordPolicyName
     * @param description
     * @param ageLimit
     * @param historyLimit
     * @param minNumberOfDigits
     * @param minNumberOfChars
     * @param minNumberOfSpecialChars
     * @param minPasswordLength
     * @param maxNumberUnsuccessfulLoginAttempts
     * @param isDeletable
     * @param isModifiable
     * @return PasswordPolicy
     * @throws ValidationException
     */
    public final PasswordPolicy createPasswordPolicy(
        String passwordPolicyName,
        String description,
        int ageLimit,
        int historyLimit,
        int minNumberOfDigits,
        int minNumberOfChars,
        int minNumberOfSpecialChars,
        int minPasswordLength,
        int maxNumberUnsuccessfulLoginAttempts,
        boolean isDeletable,
        boolean isModifiable) throws ValidationException {
        
        PasswordPolicy passwordPolicy = new PasswordPolicy();       

        passwordPolicy.setName(passwordPolicyName);
        passwordPolicy.setDescription(description);
        passwordPolicy.setAgeLimit(ageLimit);
        passwordPolicy.setHistoryLimit(historyLimit);
        passwordPolicy.setMinNumberOfDigits(minNumberOfDigits);
        passwordPolicy.setMinNumberOfChars(minNumberOfChars);
        passwordPolicy.setMinNumberOfSpecialChars(minNumberOfSpecialChars);
        passwordPolicy.setMinPasswordLength(minPasswordLength);
        passwordPolicy.setMaxNumberUnsuccessfulLoginAttempts(maxNumberUnsuccessfulLoginAttempts);
        passwordPolicy.setIsDeletable(isDeletable);
        passwordPolicy.setIsModifiable(isModifiable);
        
        return passwordPolicy;
    }
	
	/**
	 * 
	 * @param username
	 * @param firstName
	 * @param lastName
	 * @param description
	 * @param password
	 * @param multiTenancyRealm
	 * @return SecurityUser
	 * @throws ValidationException
	 * @throws PasswordPolicyException
	 */
	public final SecurityUser createSecurityUser(
		String username,
		String firstName,
		String lastName,
		String description,
		Password password,
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ValidationException, 
		PasswordPolicyException {

		String primaryEmailAddress = "";
	
		return createSecurityUser(
			username, 
			firstName, 
			lastName, 
			primaryEmailAddress,
			description,
			password,
			multiTenancyRealm);
	}	
	
    /**
     * 
     * @param username
     * @param firstName
     * @param lastName
     * @param primaryEmailAddress
     * @param description
     * @param multiTenancyRealm
     * @return SecurityUser
     * @throws ValidationException
     * @throws PasswordPolicyException
     */
    public final SecurityUser createSecurityUserWithoutPassword(
        String username,
        String firstName,
        String lastName,
        String primaryEmailAddress,
        String description,
        MultiTenancyRealm multiTenancyRealm) 
    throws 
        ValidationException, 
        PasswordPolicyException {
        
        SecurityUser securityUser = new SecurityUser();

        securityUser.setPrincipalName(username);
        securityUser.setFirstName(firstName);
        securityUser.setLastName(lastName);
        securityUser.setPrimaryEmailAddress(primaryEmailAddress);
        securityUser.setDescription(description);
        securityUser.setMultiTenancyRealm(multiTenancyRealm);
        
        boolean validatePasswords = false;
        securityUser.validate(validatePasswords);
        
        return securityUser;
    }
	
	/**
	 * 
	 * @param username
	 * @param firstName
	 * @param lastName
	 * @param primaryEmailAddress
	 * @param description
	 * @param password
	 * @param multiTenancyRealm
	 * @return SecurityUser
	 * @throws ValidationException
	 * @throws PasswordPolicyException
	 */
	public final SecurityUser createSecurityUser(
		String username,
		String firstName,
		String lastName,
		String primaryEmailAddress,
		String description,
		Password password,
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ValidationException, 
		PasswordPolicyException {
		
		SecurityUser securityUser = new SecurityUser();

		securityUser.setPrincipalName(username);
		securityUser.setFirstName(firstName);
		securityUser.setLastName(lastName);
		securityUser.setPrimaryEmailAddress(primaryEmailAddress);
		securityUser.setDescription(description);
		securityUser.setMultiTenancyRealm(multiTenancyRealm);
		securityUser.addPassword(password);
		
		securityUser.validate();
		
		return securityUser;
	}

	/**
	 * 
	 * @param username
	 * @param multiTenancyRealm
	 * @return ShadowSecurityUser
	 * @throws ValidationException
	 */
	public final ShadowSecurityUser createShadowSecurityUser(
			String username,
			MultiTenancyRealm multiTenancyRealm) throws ValidationException {
		
		ShadowSecurityUser shadowSecurityUser = new ShadowSecurityUser();

		shadowSecurityUser.setPrincipalName(username);
		shadowSecurityUser.setMultiTenancyRealm(multiTenancyRealm);
						
		shadowSecurityUser.validate();
		
		return shadowSecurityUser;
	}
	
	/**
	 * 
	 * @param username
	 * @param description
	 * @param encodedPassword
	 * @param isDeletable
	 * @param isModifiable
	 * @param multiTenancyRealm
	 * @return SystemUser
	 * @throws ValidationException
	 */
	public final SystemUser createSystemUser(
		String username,
		String description,
		String encodedPassword,
        boolean isDeletable,
        boolean isModifiable,
        MultiTenancyRealm multiTenancyRealm) throws ValidationException {
		
		SystemUser systemUser = new SystemUser();
		systemUser.setPrincipalName(username);
		systemUser.setDescription(description);
		systemUser.setEncodedPassword(encodedPassword);
		systemUser.setIsDeletable(isDeletable);
		systemUser.setIsModifiable(isModifiable);
		systemUser.setMultiTenancyRealm(multiTenancyRealm);
		
		systemUser.validate();
		
		return systemUser;
	}
		
	/**
	 * 
	 * @param groupname
	 * @param description
	 * @param assignByDefault
	 * @param memberUsers
	 * @param parentGroup
	 * @param isDeletable
	 * @param isModifiable
	 * @param multiTenancyRealm
	 * @return SecurityGroup
	 * @throws ValidationException
	 */
	public final SecurityGroup createSecurityGroup(
		String groupname,
		String description,
		boolean assignByDefault,
		Set<AbstractUser> memberUsers,
		SecurityGroup parentGroup,
		boolean isDeletable,
		boolean isModifiable,
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ValidationException {
				
		SecurityGroup securityGroup = new SecurityGroup();
		
		securityGroup.setGroupname(groupname);
		securityGroup.setDescription(description);
		securityGroup.setAssignByDefault(assignByDefault);
		securityGroup.setMultiTenancyRealm(multiTenancyRealm);
		securityGroup.setIsDeletable(isDeletable);
		securityGroup.setIsModifiable(isModifiable);
		
		if (memberUsers != null && memberUsers.size() > 0) {
			securityGroup.getMemberUsers().addAll(memberUsers);	
		}						
		
		if (parentGroup != null) {
			securityGroup.setParentGroup(parentGroup);
		}
		
		securityGroup.validate();
		
		return securityGroup;
	}

	/**
	 * 
	 * @param groupname
	 * @param multiTenancyRealm
	 * @return ShadowSecurityGroup
	 * @throws ValidationException
	 */
	public final ShadowSecurityGroup createShadowSecurityGroup(
			String groupname,
			MultiTenancyRealm multiTenancyRealm) throws ValidationException {
				
		ShadowSecurityGroup shadowSecurityGroup = new ShadowSecurityGroup();
		
		shadowSecurityGroup.setGroupname(groupname);
		shadowSecurityGroup.setMultiTenancyRealm(multiTenancyRealm);
		
		shadowSecurityGroup.validate();
		
		return shadowSecurityGroup;
	}	

    /**
     * 
     * @param rolename
     * @param displayName
     * @param description
     * @param multiTenancyRealm
     * @return SecurityRole
     * @throws ValidationException
     */
    public final SecurityRole createSecurityRole(
        String rolename,
        String displayName,
        String description,
        MultiTenancyRealm multiTenancyRealm) throws ValidationException {

        boolean assignByDefault = false;
        Set<SecurityRole> includedRoles = new TreeSet<SecurityRole>();
        boolean isDeletable = true;
        boolean isModifiable = true;        
        return this.createSecurityRole(
            rolename, 
            displayName,
            description,
            assignByDefault,
            includedRoles,
            isDeletable,
            isModifiable,
            multiTenancyRealm);
    }
		
	/**
	 * 
	 * @param rolename
	 * @param displayName
	 * @param description
	 * @param assignByDefault
	 * @param includedRoles
	 * @param isDeletable
	 * @param isModifiable
	 * @param multiTenancyRealm
	 * @return SecurityRole
	 * @throws ValidationException
	 */
	public final SecurityRole createSecurityRole(
		String rolename,
		String displayName,
		String description,
		boolean assignByDefault,
		Set<SecurityRole> includedRoles,
        boolean isDeletable,
        boolean isModifiable,		
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ValidationException {
				
		SecurityRole securityRole = new SecurityRole();
		
		securityRole.setRoleName(rolename);
		securityRole.setDisplayName(displayName);
		securityRole.setDescription(description);
		securityRole.setAssignByDefault(assignByDefault);
		securityRole.setIncludedSecurityRoles(includedRoles);
		securityRole.setMultiTenancyRealm(multiTenancyRealm);
		securityRole.setIsDeletable(isDeletable);
		securityRole.setIsModifiable(isModifiable);
		
		securityRole.validate();
		
		return securityRole;
	}

	/**
	 * 
	 * @param initiatingUsername
	 * @param eventDetails
	 * @param originatingIpAddress
	 * @param originatingHostname
	 * @param eventDate
	 * @param realmName
	 * @return AuditEvent
	 * @throws ValidationException
	 */
	public final AuditEvent createAuditEvent(
		String initiatingUsername,
		String eventDetails,
		String originatingIpAddress,
		String originatingHostname,
		java.util.Date eventDate,
		String realmName) 
	throws 
		ValidationException {
		
		AuditEvent auditEvent = new AuditEvent(
		    initiatingUsername,
            eventDetails,
            originatingIpAddress,
            originatingHostname,
            eventDate,
            realmName); 
		
		auditEvent.validate();
		
		return auditEvent;
	}

	/**
	 * 
	 * @param sourceRepositoryName
	 * @param principalType
	 * @param principalName
	 * @param nameValuePairs
	 * @param reason
	 * @param multiTenancyRealm
	 * @return MigrationRecord
	 * @throws ValidationException
	 */
	public final MigrationRecord createMigrationRecord(
		String sourceRepositoryName, 
		String principalType,
		String principalName, 
		String nameValuePairs,
		String reason,
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ValidationException {

		MigrationRecord migrationRecord = new MigrationRecord(
				sourceRepositoryName, 
				principalType,
				principalName, 
				nameValuePairs,
				reason,
				multiTenancyRealm);
		
		migrationRecord.validate();
		
		return migrationRecord;
	}
}