/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2011 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.persistence.dao.hibernate;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.hibernate.SessionFactory;

import com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.AbstractGroup;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.DomainObjectFactory;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipal;
import com.compuware.frameworks.security.service.api.model.SecurityRole;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public final class SecurityRoleHibernateDao extends BaseHibernateDao implements ISecurityRoleDao {
	
    /**
     * 
     * @param sessionFactory
     */
    public SecurityRoleHibernateDao(SessionFactory sessionFactory) {
    	super(sessionFactory);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#securityRoleExists(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public boolean securityRoleExists(String securityRoleName, MultiTenancyRealm multiTenancyRealm) {
    
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_ROLE + " securityRole where securityRole.roleName=? and securityRole.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSecurityRole")
    	.setParameter(0, securityRoleName)
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        if (list.size() == 0) {
        	return false;
        }
        return true;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#createSecurityRole(java.lang.String, java.lang.String, java.lang.String, boolean, boolean, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
	public SecurityRole createSecurityRole(
	   String roleName,
	   String displayName,
	   String description,
	   boolean assignByDefault,
	   boolean isDeletable,
	   boolean isModifiable,
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectAlreadyExistsException,
	   ValidationException {
		Set<SecurityRole> includedRoles = new TreeSet<SecurityRole>();
		return createSecurityRole(
			roleName,
			displayName,
			description,
			assignByDefault,
			includedRoles,
			isDeletable,
			isModifiable,
			multiTenancyRealm);
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#createSecurityRole(java.lang.String, java.lang.String, java.lang.String, boolean, java.util.Set, boolean, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public SecurityRole createSecurityRole(
	   String roleName,
	   String displayName,
	   String description,
	   boolean assignByDefault,
	   Set<SecurityRole> includedRoles,
	   boolean isDeletable,
	   boolean isModifiable,
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectAlreadyExistsException,
	   ValidationException {
		
		if (securityRoleExists(roleName, multiTenancyRealm)) {
			throw new ObjectAlreadyExistsException("Security Role: [" + roleName + "] already exists in realm: [" + multiTenancyRealm + "].");
		}		
		
		SecurityRole securityRole = new DomainObjectFactory().createSecurityRole(
			roleName, 
			displayName,
			description,
			assignByDefault,
			includedRoles,
			isDeletable,
			isModifiable,
			multiTenancyRealm);
		
		this.sessionFactory.getCurrentSession().save(securityRole);
		
		return securityRole;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getSecurityRole(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public SecurityRole getSecurityRole(
		String roleName,	
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ObjectNotFoundException {

        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_ROLE + " securityRole where securityRole.roleName=? and securityRole.multiTenancyRealm=?")
    	.setParameter(0, roleName)
    	.setParameter(1, multiTenancyRealm)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSecurityRole")    	    	
    	.list();
    	
        SecurityRole securityRole = null;
        if (list != null && list.size() == 1) {
        	securityRole = (SecurityRole)list.get(0);	
        } else if (list.size() == 0) {
        	throw new ObjectNotFoundException("Cannot find securityRole with roleName: [" + roleName + "].");
        } else {
        	throw new IllegalStateException("There exists: [" + list.size()+ "] SecurityRoles with roleName: [" + roleName + "] in realm: [" + multiTenancyRealm + "] and this should not be as both together should be unique.");
        }
        
        return securityRole;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getAllSecurityRoles(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */	
	@SuppressWarnings("unchecked")
	public Collection<SecurityRole> getAllSecurityRoles(MultiTenancyRealm multiTenancyRealm) {
		
        List<Object> list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_ROLE + " securityRole where securityRole.multiTenancyRealm=?")
    	.setParameter(0, multiTenancyRealm)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllSecurityRoles")    	    	
    	.list();
        
        Collection<SecurityRole> securityRoles = new TreeSet<SecurityRole>();
        Iterator<Object> iterator = list.iterator();
        while (iterator.hasNext()) {
        	securityRoles.add((SecurityRole)iterator.next());
        }
        return securityRoles;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getAllDefaultSecurityRoles(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
    public Collection<SecurityRole> getAllDefaultSecurityRoles(MultiTenancyRealm multiTenancyRealm) {

        @SuppressWarnings(RAW_TYPES)
        List list = this.sessionFactory.getCurrentSession()
        .createQuery(FROM + SECURITY_ROLE + " securityRole where securityRole.multiTenancyRealm=? and securityRole.assignByDefault=?")
        .setParameter(0, multiTenancyRealm)
        .setParameter(1, true)
        .setCacheable(true)
        .setCacheRegion("com.compuware.frameworks.security.persistence.getAllSecurityRoles")               
        .list();
        
        Collection<SecurityRole> securityRoles = new TreeSet<SecurityRole>();
        int size = list.size();
        if (list != null && size > 0) {
            for (int i=0; i < size; i++) {
                SecurityRole securityRole = (SecurityRole)list.get(i);
                securityRoles.add(securityRole);
            }
        }
        
        return securityRoles;
    }
	
	/*
	 * TODO: TDM: This method may remain if all security roles for all realms can peacibly co-exist such that one role hierarchy voter
	 * can be used regardless of the realm.
	 * 
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getAllSecurityRoles()
	 */
	@SuppressWarnings("unchecked")
	public Collection<SecurityRole> getAllSecurityRoles() {

        List<Object> list = this.sessionFactory.getCurrentSession()
        .createQuery(FROM + SECURITY_ROLE + " securityRole")
        .setCacheable(true)
        .setCacheRegion("com.compuware.frameworks.security.persistence.getAllSecurityRoles")                
        .list();
        
        Collection<SecurityRole> securityRoles = new TreeSet<SecurityRole>();
        Iterator<Object> iterator = list.iterator();
        while (iterator.hasNext()) {
            securityRoles.add((SecurityRole)iterator.next());
        }
        return securityRoles;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getAllSecurityRolesForUser(com.compuware.frameworks.security.service.api.model.AbstractUser, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityRole> getAllSecurityRolesForUser(AbstractUser user, MultiTenancyRealm multiTenancyRealm) {
		
		return getAllSecurityRolesForSecurityPrincipal(user, multiTenancyRealm);
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getAllSecurityRolesForGroup(com.compuware.frameworks.security.service.api.model.AbstractGroup, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityRole> getAllSecurityRolesForGroup(AbstractGroup group, MultiTenancyRealm multiTenancyRealm) {

		return getAllSecurityRolesForSecurityPrincipal(group, multiTenancyRealm);
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getAllSecurityRolesForSecurityPrincipal(com.compuware.frameworks.security.service.api.model.SecurityPrincipal, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityRole> getAllSecurityRolesForSecurityPrincipal(SecurityPrincipal securityPrincipal, MultiTenancyRealm multiTenancyRealm) {

		Collection<SecurityRole> securityRoles = new TreeSet<SecurityRole>();
		
        Iterator<SecurityRole> iterator = this.getAllSecurityRoles(multiTenancyRealm).iterator();
        while (iterator.hasNext()) {
        	SecurityRole securityRole = iterator.next();
        	if (securityRole.getMemberSecurityPrincipals().contains(securityPrincipal)) {
        		securityRoles.add(securityRole);
        	}
        }
        
        return securityRoles;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getAllSecurityPrincipalsForSecurityRole(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityPrincipal> getAllSecurityPrincipalsForSecurityRole(String roleName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {

        Iterator<SecurityRole> iterator = this.getAllSecurityRoles(multiTenancyRealm).iterator();
        while (iterator.hasNext()) {
        	SecurityRole securityRole = iterator.next();
        	if (securityRole.getRoleName().equals(roleName)) {
        		return securityRole.getMemberSecurityPrincipals();
        	}
        }
        throw new ObjectNotFoundException("Cannot find securityRole with roleName: [" + roleName + "].");
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao#getAllIncludedSecurityRolesForSecurityRole(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityRole> getAllIncludedSecurityRolesForSecurityRole(String roleName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException {

        Iterator<SecurityRole> iterator = this.getAllSecurityRoles(multiTenancyRealm).iterator();
        while (iterator.hasNext()) {
            SecurityRole securityRole = iterator.next();
            if (securityRole.getRoleName().equals(roleName)) {
                return securityRole.getIncludedSecurityRoles();
            }
        }
        throw new ObjectNotFoundException("Cannot find securityRole with roleName: [" + roleName + "].");
	}
}