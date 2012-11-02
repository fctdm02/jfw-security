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
import java.util.List;

import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;
import org.springframework.stereotype.Repository;

import com.compuware.frameworks.security.persistence.dao.ICompuwareSecurityDao;
import com.compuware.frameworks.security.service.api.management.exception.NonDeletableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.NonModifiableObjectException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.management.exception.StaleObjectException;
import com.compuware.frameworks.security.service.api.model.AbstractGroup;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.AuditEvent;
import com.compuware.frameworks.security.service.api.model.DomainObject;
import com.compuware.frameworks.security.service.api.model.MigrationRecord;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.Password;
import com.compuware.frameworks.security.service.api.model.PasswordPolicy;
import com.compuware.frameworks.security.service.api.model.SecurityGroup;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipal;
import com.compuware.frameworks.security.service.api.model.SecurityRole;
import com.compuware.frameworks.security.service.api.model.SecurityUser;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.SystemUser;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
@Repository
public abstract class BaseHibernateDao implements ICompuwareSecurityDao {
	
	/* */
	private final Logger logger = Logger.getLogger(BaseHibernateDao.class);


	/** */
	public static final String CRITERIA_PRINCIPAL_NAME = "principalName";
	/** */
	public static final String OPERATOR_LIKE = "%";
    /** */
    public static final String CRITERIA_MULTI_TENANCY_REALM = "multiTenancyRealm";
	
	/** */
	public static final String RAW_TYPES = "rawtypes";
	
	/** */
	public static final String FROM = "from ";
	
	/** Maximum results to return; used for auditing and migration */
	public static final int MAX_RESULTS = 1000;
	
	/** */
	public static final String AUDIT_EVENT = AuditEvent.class.getName();

	/** */
	public static final String MIGRATION_RECORD = MigrationRecord.class.getName();
	
	/** */
	public static final String MULTI_TENANCY_REALM = MultiTenancyRealm.class.getName();
	
	/** */
	public static final String PASSWORD = Password.class.getName();

	/** */
	public static final String PASSWORD_POLICY = PasswordPolicy.class.getName();
		
	/** */
	public static final String SECURITY_PRINCIPAL = SecurityPrincipal.class.getName();

	/** */
	public static final String ABSTRACT_USER = AbstractUser.class.getName();
	
	/** */
	public static final String SECURITY_USER = SecurityUser.class.getName();

	/** */
	public static final String SHADOW_SECURITY_USER = ShadowSecurityUser.class.getName();
	
	/** */
	public static final String SYSTEM_USER = SystemUser.class.getName();

	/** */
	public static final String ABSTRACT_GROUP = AbstractGroup.class.getName();
	
	/** */
	public static final String SECURITY_GROUP = SecurityGroup.class.getName();

	/** */
	public static final String SHADOW_SECURITY_GROUP = ShadowSecurityGroup.class.getName();
		
	/** */
	public static final String SECURITY_ROLE = SecurityRole.class.getName();
	
	
	/** */
    protected SessionFactory sessionFactory;
    
    /**
     * 
     * @param sessionFactory
     */
    public BaseHibernateDao(SessionFactory sessionFactory) {
    	setSessionFactory(sessionFactory);
    }

    /**
     * 
     * @param sessionFactory
     */
    public final void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }
    
    /**
     * 
     * @param realmName
     * @return
     * @throws MultiTenancyRealmNotFoundException
     */
    public MultiTenancyRealm getMultiTenancyRealmByRealmName(String realmName) throws ObjectNotFoundException {
    	
		MultiTenancyRealm multiTenancyRealm = null;
		
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + MULTI_TENANCY_REALM + " multiTenancyRealm where multiTenancyRealm.realmName=?")
    	.setParameter(0, realmName)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getMultiTenancyRealmByRealmName")
    	.list();
    	
        if (list != null && list.size() == 1) {
        	multiTenancyRealm = (MultiTenancyRealm)list.get(0);	
        } else if (list.size() == 0) {
        	throw new ObjectNotFoundException("BaseHibernateDao: Cannot find MultiTenancyRealm with realmName: [" + realmName + "].  Result List: " + list);
        }
        
        return multiTenancyRealm;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ICompuwareSecurityDao#getDomainObjectById(java.lang.Class, java.io.Serializable)
     */
    @SuppressWarnings(RAW_TYPES)
	public final DomainObject getDomainObjectById(Class clazz, Serializable id) throws ObjectNotFoundException {
		
		boolean nullIfNotFound = false;
        return getDomainObjectByIdNullIfNotFound(clazz, id, nullIfNotFound);
	}

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ICompuwareSecurityDao#getDomainObjectByIdNullIfNotFound(java.lang.Class, java.io.Serializable)
     */
    @SuppressWarnings(RAW_TYPES)
    public final DomainObject getDomainObjectByIdNullIfNotFound(Class clazz, Serializable id) {
    	
		boolean nullIfNotFound = true;
		try {
			return getDomainObjectByIdNullIfNotFound(clazz, id, nullIfNotFound);	
		} catch (ObjectNotFoundException onfe) {
			throw new IllegalStateException("An ObjectNotFoundException should not have been thrown when 'nullIfNotFound' was set to 'true'.");
		}
    }
    
	/*
	 * 
	 * @param clazz
	 * @param id
	 * @param nullIfNotFound
	 * @return
	 * @throws ObjectNotFoundException
	 */
	@SuppressWarnings(RAW_TYPES)
    private DomainObject getDomainObjectByIdNullIfNotFound(Class clazz, Serializable id, boolean nullIfNotFound) throws ObjectNotFoundException {

		String domainObjectClass = null;
		String domainObjectId = null;
		if (clazz == AuditEvent.class) {
			domainObjectClass = AUDIT_EVENT;
			domainObjectId = "auditEventId";
		} else if (clazz == MigrationRecord.class) {
			domainObjectClass = MIGRATION_RECORD;
			domainObjectId = "migrationRecordId";			
		} else if (clazz == MultiTenancyRealm.class) {
			domainObjectClass = MULTI_TENANCY_REALM;
			domainObjectId = "multiTenancyRealmId";
		} else if (clazz == Password.class) {
			domainObjectClass = PASSWORD;
			domainObjectId = "passwordId";
		} else if (clazz == PasswordPolicy.class) {
			domainObjectClass = PASSWORD_POLICY;
			domainObjectId = "passwordPolicyId";
		} else if (clazz == SecurityPrincipal.class) {
			domainObjectClass = SECURITY_PRINCIPAL;
			domainObjectId = "securityPrincipalId";
		} else if (clazz == AbstractUser.class) {
			domainObjectClass = ABSTRACT_USER;
			domainObjectId = "securityPrincipalId";
        } else if (clazz == AbstractGroup.class) {
            domainObjectClass = ABSTRACT_GROUP;
            domainObjectId = "securityPrincipalId";         			
		} else if (clazz == SecurityUser.class) {
			domainObjectClass = SECURITY_USER;
			domainObjectId = "securityPrincipalId";
		} else if (clazz == ShadowSecurityUser.class) {
			domainObjectClass = SHADOW_SECURITY_USER;
			domainObjectId = "securityPrincipalId";
		} else if (clazz == SystemUser.class) {
			domainObjectClass = SYSTEM_USER;
			domainObjectId = "securityPrincipalId";			
		} else if (clazz == SecurityGroup.class) {
			domainObjectClass = SECURITY_GROUP;
			domainObjectId = "securityPrincipalId";						
		} else if (clazz == ShadowSecurityGroup.class) {
			domainObjectClass = SHADOW_SECURITY_GROUP;
			domainObjectId = "securityPrincipalId";
		} else if (clazz == SecurityRole.class) {
			domainObjectClass = SECURITY_ROLE;
			domainObjectId = "securityRoleId";
		} else {
			throw new IllegalStateException("Unsupported domain object class for getDomainObjectByIdNullIfNotFound: " + clazz.getCanonicalName());
		}
		
    	List list = this.sessionFactory.getCurrentSession()
    	   .createQuery(FROM + domainObjectClass + " domainObject where domainObject." + domainObjectId + "=?")
    	   .setParameter(0, id)
    	   .setCacheable(true)
    	   .setCacheRegion("com.compuware.frameworks.security.persistence.getDomainObjectById")
    	   .list();
 	
     DomainObject domainObject = null;
     if (list.size() > 0) {
    	 domainObject = (DomainObject)list.get(0);   
     }

     if (!nullIfNotFound && domainObject == null) {
    	 throw new ObjectNotFoundException("Cannot find domainObject of type: [" + domainObjectClass + "] with an " + domainObjectId + ": [" + id + "].");    	 
     }
     
     return domainObject;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ICompuwareSecurityDao#save(com.compuware.frameworks.security.service.api.model.DomainObject)
     */
	public final void save(DomainObject domainObject) throws ValidationException, ObjectAlreadyExistsException {
		
		domainObject.validate();
		
		logger.debug("Saving domain object: [" + domainObject + "].");
		this.sessionFactory.getCurrentSession().save(domainObject);
		this.sessionFactory.getCurrentSession().flush();
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ICompuwareSecurityDao#update(com.compuware.frameworks.security.service.api.model.DomainObject)
	 */
	public final void update(DomainObject domainObject) 
	throws 
	    ObjectNotFoundException, 
	    ValidationException, 
	    StaleObjectException,
	    NonModifiableObjectException {
	    
        if (domainObject.getPersistentIdentity() == null) {
            throw new ObjectNotFoundException("Cannot update a non-persisted instance of: " 
                + domainObject.getClass().getName() 
                + " with natural identity: " 
                + domainObject.getNaturalIdentity());
        }
	    		
		// Make sure that the domain object is in a valid state (business rules wise) before we save to the DB.
		domainObject.validate();
				
		boolean nullIfNotFound = false;
		DomainObject currentlyPersistedDomainObject = (DomainObject)this.getDomainObjectByIdNullIfNotFound(
			domainObject.getClass(), 
			domainObject.getPersistentIdentity(), 
			nullIfNotFound);
		
		if (currentlyPersistedDomainObject != null) {
			
			// Make sure the domainObject to be deleted isn't stale.
			Integer currentlyPersistedDomainObjectVersion = currentlyPersistedDomainObject.getVersion();
			Integer domainObjectVersion = domainObject.getVersion();
			if (currentlyPersistedDomainObjectVersion != null
				&& domainObjectVersion != null
				&& currentlyPersistedDomainObjectVersion.intValue() != domainObjectVersion.intValue()) {
				throw new StaleObjectException("Cannot update a stale instance of: " 
					+ domainObject.getClass().getName() 
					+ " with natural identity: " 
					+ domainObject.getNaturalIdentity() 
					+ " and persistent identity: " 
					+ domainObject.getPersistentIdentity()
					+ " because the currently persisted version is: " 
					+ currentlyPersistedDomainObject.getVersion()
					+ ", yet the version on the stale object being passed in is: "
					+ domainObject.getVersion()
					+ ".  Please refresh/examine and try again if needed.");
			}
			
			this.evict(currentlyPersistedDomainObject);
		} else {
			throw new ObjectNotFoundException("Could not find a persisted instance of: " 
				+ domainObject.getClass().getName() 
				+ " with natural identity: " 
				+ domainObject.getNaturalIdentity() 
				+ " and persistent identity: " 
				+ domainObject.getPersistentIdentity());
		}

		logger.debug("Updating domain object: [" + domainObject + "].");
		this.sessionFactory.getCurrentSession().update(domainObject);
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ICompuwareSecurityDao#delete(com.compuware.frameworks.security.service.api.model.DomainObject)
	 */
	public final void delete(DomainObject domainObject) 
	throws 
	    ObjectNotFoundException, 
	    NonDeletableObjectException {
	    
		if (domainObject.getPersistentIdentity() == null) {
			throw new ObjectNotFoundException("Cannot delete a non-persisted instance of: " 
				+ domainObject.getClass().getName() 
				+ " with natural identity: " 
				+ domainObject.getNaturalIdentity());
		}

        if (!domainObject.getIsDeletable()) {
            throw new NonDeletableObjectException("Cannot delete a non-deletable instance of: " 
                + domainObject.getClass().getName() 
                + " with natural identity: " 
                + domainObject.getNaturalIdentity());
        }
		
		boolean nullIfNotFound = false;
		DomainObject oldDomainObject = (DomainObject)this.getDomainObjectByIdNullIfNotFound(domainObject.getClass(), domainObject.getPersistentIdentity(), nullIfNotFound);
		if (oldDomainObject != null) {
			this.evict(oldDomainObject);
		} else {
			throw new ObjectNotFoundException("Could not find a persisted instance of: " 
				+ domainObject.getClass().getName() 
				+ " with natural identity: " 
				+ domainObject.getNaturalIdentity() 
				+ " and persistent identity: " 
				+ domainObject.getPersistentIdentity());
		}

		logger.debug("Deleting " + domainObject);
		this.sessionFactory.getCurrentSession().delete(domainObject);
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ICompuwareSecurityDao#evict(com.compuware.frameworks.security.service.api.model.DomainObject)
	 */
	public final void evict(DomainObject domainObject) throws ObjectNotFoundException {
		
		logger.debug("Evicting " + domainObject);
		this.sessionFactory.getCurrentSession().evict(domainObject);
	}
}