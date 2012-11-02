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
public class SecurityGroup extends AbstractGroup {

	/** */
	private static final long serialVersionUID = 1L;

    /** */
    private boolean assignByDefault;
	
	/** */
	private Set<AbstractUser> memberUsers = new TreeSet<AbstractUser>();

	/** Used to facilitate a group hierarchy (like in LDAP). */
	private SecurityGroup parentGroup;

	/**
	 * 
	 */
	public SecurityGroup() {
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
	 * 
	 * @return Set<AbstractUser>
	 */
	@XmlElementWrapper(name="memberUsers")
	@XmlElement(name="abstractUser")
	public final Set<AbstractUser> getMemberUsers() {
		return this.memberUsers;
	}

	/**
	 * 
	 * @return Only those member users that are SecurityUsers 
	 */
	public final Set<SecurityUser> getSecurityUserMembers() {
		Set<SecurityUser> set = new TreeSet<SecurityUser>();
		Iterator<AbstractUser> iterator = this.memberUsers.iterator();
		while (iterator.hasNext()) {
			AbstractUser user = iterator.next();
			if (user instanceof SecurityUser) {
				set.add((SecurityUser)user);
			}
		}
		return set;
	}

	/**
	 * 
	 * @return Only those member users that are SecurityUsers with an unlocked account 
	 */
	public final Set<SecurityUser> getActiveSecurityUserMembers() {
		Set<SecurityUser> set = new TreeSet<SecurityUser>();
		Iterator<AbstractUser> iterator = this.memberUsers.iterator();
		while (iterator.hasNext()) {
			AbstractUser user = iterator.next();
			if (user instanceof SecurityUser) {
				SecurityUser securityUser = (SecurityUser)user;
				if (securityUser.isAccountNonLocked()) {
					set.add((SecurityUser)user);	
				}
			}
		}
		return set;
	}

	/**
	 * 
	 * @return Only those member users that are SecurityUsers with a locked account 
	 */
	public final Set<SecurityUser> getInactiveSecurityUserMembers() {
		Set<SecurityUser> set = new TreeSet<SecurityUser>();
		Iterator<AbstractUser> iterator = this.memberUsers.iterator();
		while (iterator.hasNext()) {
			AbstractUser user = iterator.next();
			if (user instanceof SecurityUser) {
				SecurityUser securityUser = (SecurityUser)user;
				if (!securityUser.isAccountNonLocked()) {
					set.add((SecurityUser)user);	
				}
			}
		}
		return set;
	}
	
	/**
	 * 
	 * @return Only those member users that are SystemUsers 
	 */
	public final Set<SystemUser> getSystemUserMembers() {
		Set<SystemUser> set = new TreeSet<SystemUser>();
		Iterator<AbstractUser> iterator = this.memberUsers.iterator();
		while (iterator.hasNext()) {
			AbstractUser user = iterator.next();
			if (user instanceof SystemUser) {
				set.add((SystemUser)user);
			}
		}
		return set;
	}
	
	/**
	 * 
	 * @param memberUsers
	 */
	public final void setMemberUsers(Set<AbstractUser> memberUsers) {
		this.memberUsers.addAll(memberUsers);
	}

	/**
	 * 
	 * @return SecurityGroup
	 */
	@XmlElement
	public final SecurityGroup getParentGroup() {
		return this.parentGroup;
	}

	/**
	 * 
	 * @param parentGroup
	 */
	public final void setParentGroup(SecurityGroup parentGroup) {
		this.parentGroup = parentGroup;
	}

	/**
	 * 
	 * @param user
	 * @throws ObjectAlreadyExistsException
	 */
	public final void addUser(AbstractUser user) throws ObjectAlreadyExistsException {
		if (user == null) {
			throw new ServiceException("User cannot be null.");
		}
		if (this.memberUsers.contains(user)) {
			throw new ObjectAlreadyExistsException("user: " 
				+ user 
				+ " has already been associated with security group: " 
				+ this);
		}
		this.memberUsers.add(user);
	}

	/**
	 * 
	 * @param user
	 * @return true if the user was removed
	 */
	public final boolean removeUser(AbstractUser user) {
		if (user == null) {
			throw new ServiceException("User cannot be null.");
		}
		return this.memberUsers.remove(user);
	}

	/**
	 * 
	 * @return the full path of the group.
	 */
	public final String getPath() {
		String path = getGroupname();
		if (parentGroup != null) {
			return parentGroup.getPath() + "\\" + path;
		}
		return path;
	}

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
    */
   public void validate() throws ValidationException {

       super.validate();
       
       if (this.getGroupname().length() < this.getMultiTenancyRealm().getMinimumGroupnameLength()) {
           
           String reason = ValidationException.REASON_MINIMUM_LENGTH_NOT_SATISFIED;
           reason = reason.replace(ValidationException.TOKEN_ZERO, Integer.toString(this.getMultiTenancyRealm().getMinimumGroupnameLength()));
           throw new ValidationException(ValidationException.FIELD_GROUPNAME, reason);
       }
   }
}