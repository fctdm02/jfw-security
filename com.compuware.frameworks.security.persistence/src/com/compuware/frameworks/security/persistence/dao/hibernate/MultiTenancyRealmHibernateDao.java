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

import java.io.Serializable;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;

import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.service.api.management.exception.NonDeletableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.DomainObjectFactory;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.PasswordPolicy;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public final class MultiTenancyRealmHibernateDao extends BaseHibernateDao implements IMultiTenancyRealmDao {
	
	/* */
	private final Logger logger = Logger.getLogger(MultiTenancyRealmHibernateDao.class);
			
    /**
     * 
     * @param sessionFactory
     */
    public MultiTenancyRealmHibernateDao(SessionFactory sessionFactory) {
    	super(sessionFactory);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao#multiTenancyRealmExists(java.lang.String)
     */
	public boolean multiTenancyRealmExists(String realmName) {
		
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + MULTI_TENANCY_REALM + " multiTenancyRealm where multiTenancyRealm.realmName=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getMultiTenancyRealmByRealmName")
    	.setParameter(0, realmName)
    	.list();
    	
        if (list.size() == 0) {
        	return false;
        }
        return true;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao#passwordPolicyExists(java.lang.String, java.lang.String)
	 */
	public boolean passwordPolicyExists(String passwordPolicyName, String realmName) {

	    Iterator<MultiTenancyRealm> multiTenancyRealmIterator = this.getAllMultiTenancyRealms().iterator();
	    while (multiTenancyRealmIterator.hasNext()) {
	        
	        MultiTenancyRealm multiTenancyRealm = multiTenancyRealmIterator.next();
	        if (multiTenancyRealm.getRealmName().equalsIgnoreCase(realmName)) {

	            Iterator<PasswordPolicy> passwordPolicyIterator = multiTenancyRealm.getPasswordPolicies().iterator();
	            while (passwordPolicyIterator.hasNext()) {
	                
	                PasswordPolicy passwordPolicy = passwordPolicyIterator.next();
	                if (passwordPolicy.getName().equalsIgnoreCase(passwordPolicyName)) {
	                    
	                    return true; 
	                }
	            }
	        }
	    }
	    return false;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao#createMultiTenancyRealm(java.lang.String, java.lang.String, java.lang.String, java.util.Set, boolean, boolean)
	 */
	public MultiTenancyRealm createMultiTenancyRealm(
		String realmName,
		String description,
		String ldapBaseDn,
		Set<PasswordPolicy> passwordPolicies,
        boolean isDeletable,
        boolean isModifiable) 
	throws 
		ObjectAlreadyExistsException, 
		ValidationException {
		
		if (multiTenancyRealmExists(realmName)) {
			throw new ObjectAlreadyExistsException("Realm: [" + realmName + "] already exists.");
		}		
		
		MultiTenancyRealm multiTenancyRealm = new DomainObjectFactory().createMultiTenancyRealm(
				realmName, 
				description, 
				ldapBaseDn, 
				passwordPolicies,
				isDeletable,
				isModifiable);
		
		Serializable id = this.sessionFactory.getCurrentSession().save(multiTenancyRealm);	
		logger.debug("Created realm with id: [" + id + "]: " + multiTenancyRealm.getRealmName());
		
		return multiTenancyRealm;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao#createPasswordPolicy(java.lang.String, java.lang.String, int, int, int, int, int, int, int, boolean, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
    public PasswordPolicy createPasswordPolicy(
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
        boolean isModifiable,
        MultiTenancyRealm multiTenancyRealm)
    throws 
        ObjectAlreadyExistsException, 
        ValidationException {

        if (passwordPolicyExists(passwordPolicyName, multiTenancyRealm.getRealmName())) {
            throw new ObjectAlreadyExistsException("Password policy: [" + passwordPolicyName + "] already exists in realm: [" + multiTenancyRealm.getRealmName() + "].");
        }
        
        multiTenancyRealm = (MultiTenancyRealm)this.sessionFactory.getCurrentSession().load(MultiTenancyRealm.class, multiTenancyRealm.getPersistentIdentity());
        
        PasswordPolicy passwordPolicy = new DomainObjectFactory().createPasswordPolicy(
            passwordPolicyName, 
            description, 
            ageLimit, 
            historyLimit, 
            minNumberOfDigits, 
            minNumberOfChars, 
            minNumberOfSpecialChars, 
            minPasswordLength, 
            maxNumberUnsuccessfulLoginAttempts,
            isDeletable,
            isModifiable);
        multiTenancyRealm.addPasswordPolicy(passwordPolicy);
        
        this.sessionFactory.getCurrentSession().save(passwordPolicy);
        this.sessionFactory.getCurrentSession().flush();
        
        logger.debug("Created password policy with id: [" + passwordPolicy.getPersistentIdentity() + "]: " + passwordPolicy.getName() + " in realm: [" + multiTenancyRealm.getRealmName() + "].");
        
        return passwordPolicy;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao#deletePasswordPolicy(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public void deletePasswordPolicy(String passwordPolicyName, MultiTenancyRealm multiTenancyRealm) throws ObjectNotFoundException, NonDeletableObjectException {
       
        multiTenancyRealm = (MultiTenancyRealm)this.sessionFactory.getCurrentSession().load(MultiTenancyRealm.class, multiTenancyRealm.getPersistentIdentity());
        multiTenancyRealm.getPasswordPolicies();
        PasswordPolicy passwordPolicyToDelete = multiTenancyRealm.getPasswordPolicyByPasswordPolicyName(passwordPolicyName);
       
        if (!passwordPolicyToDelete.getIsDeletable()) {
            throw new NonDeletableObjectException("Cannot delete a non-deletable instance of: " 
                + passwordPolicyToDelete.getClass().getName() 
                + " with natural identity: " 
                + passwordPolicyToDelete.getNaturalIdentity());
        }
        
        multiTenancyRealm.removePasswordPolicy(passwordPolicyName);
        
        this.sessionFactory.getCurrentSession().delete(passwordPolicyToDelete);
        this.sessionFactory.getCurrentSession().flush();
    }

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.hibernate.BaseHibernateDao#getMultiTenancyRealmByRealmName(java.lang.String)
	 */
	public MultiTenancyRealm getMultiTenancyRealmByRealmName(
		String realmName) 
	throws 
		ObjectNotFoundException {
		
		return super.getMultiTenancyRealmByRealmName(realmName);
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao#getAllMultiTenancyRealms()
	 */
	@SuppressWarnings("unchecked")
	public Collection<MultiTenancyRealm> getAllMultiTenancyRealms() {
		
        return this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + MULTI_TENANCY_REALM)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllMultiTenancyRealms")
    	.list();
	}
}