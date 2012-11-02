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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.hibernate.Criteria;
import org.hibernate.FetchMode;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Criterion;
import org.hibernate.criterion.Restrictions;

import com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.management.exception.ObjectNotFoundException;
import com.compuware.frameworks.security.service.api.model.AbstractGroup;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.DomainObjectFactory;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.SecurityGroup;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipal;
import com.compuware.frameworks.security.service.api.model.SecurityPrincipalComparator;
import com.compuware.frameworks.security.service.api.model.SecurityUser;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityGroup;
import com.compuware.frameworks.security.service.api.model.ShadowSecurityUser;
import com.compuware.frameworks.security.service.api.model.SystemUser;
import com.compuware.frameworks.security.service.api.model.exception.PasswordPolicyException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * @author tmyers
 */
public final class SecurityPrincipalHibernateDao extends BaseHibernateDao implements ISecurityPrincipalDao {
	    
    /**
     * 
     * @param sessionFactory
     */
    public SecurityPrincipalHibernateDao(SessionFactory sessionFactory) {
    	super(sessionFactory);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#securityPrincipalExists(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public boolean securityPrincipalExists(String securityPrincipalName, MultiTenancyRealm multiTenancyRealm) {
    
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_PRINCIPAL + " securityPrincipal where lower(securityPrincipal.principalName)=? and securityPrincipal.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSecurityPrincipal")    	
    	.setParameter(0, securityPrincipalName.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        if (list.size() == 0) {
        	return false;
        }
        return true;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getSecurityPrincipalByPrincipalName(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityPrincipal getSecurityPrincipalByPrincipalName(
	   String securityPrincipalName,	
	   MultiTenancyRealm multiTenancyRealm) 
	throws
	   ObjectNotFoundException {
	
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_PRINCIPAL + " securityPrincipal where lower(securityPrincipal.principalName)=? and securityPrincipal.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSecurityPrincipal")    	
    	.setParameter(0, securityPrincipalName.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        SecurityPrincipal securityPrincipal = null;
        if (list.size() > 0) {
        	securityPrincipal = (SecurityPrincipal)list.get(0);	
        } else {
        	throw new ObjectNotFoundException("Cannot find securityPrincipal with principalName: [" + securityPrincipalName + "].");
        }
        
        return securityPrincipal;
	}
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getUserByUsername(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public AbstractUser getUserByUsername(
       String username, 
       MultiTenancyRealm multiTenancyRealm)
    throws
       ObjectNotFoundException {
    	
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + ABSTRACT_USER + " abstractUser where lower(abstractUser.principalName)=? and abstractUser.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSecurityPrincipal")    	
    	.setParameter(0, username.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        AbstractUser abstractUser = null;
        if (list.size() > 0) {
        	abstractUser = (AbstractUser)list.get(0);	
        } else {
        	throw new ObjectNotFoundException("Cannot find user with username: [" + username + "].");
        }
        
        return abstractUser;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getSystemUserByUsername(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SystemUser getSystemUserByUsername(
       String username, 
       MultiTenancyRealm multiTenancyRealm)
    throws
       ObjectNotFoundException {
    	
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SYSTEM_USER + " systemUser where lower(systemUser.principalName)=? and systemUser.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSystemUser")    	
    	.setParameter(0, username.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        if (list.size() == 1) {
        	return (SystemUser)list.get(0);	
        } else {
        	throw new ObjectNotFoundException("Cannot find system user with username: [" + username + "].");
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getSecurityUserByUsername(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public SecurityUser getSecurityUserByUsername(
       String username, 
       MultiTenancyRealm multiTenancyRealm)
    throws
       ObjectNotFoundException {
    	
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_USER + " securityUser where lower(securityUser.principalName)=? and securityUser.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSecurityUser")    	
    	.setParameter(0, username.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        if (list.size() == 1) {
        	return (SecurityUser)list.get(0);	
        } else {
        	throw new ObjectNotFoundException("Cannot find security user with username: [" + username + "].");
        }
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getShadowSecurityUserByUsername(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public ShadowSecurityUser getShadowSecurityUserByUsername(
       String username, 
       MultiTenancyRealm multiTenancyRealm) {
    	
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SHADOW_SECURITY_USER + " shadowSecurityUser where lower(shadowSecurityUser.principalName)=? and shadowSecurityUser.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getShadowSecurityUser")    	
    	.setParameter(0, username.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        ShadowSecurityUser shadowSecurityUser = null;
        if (list.size() == 1) {
        	shadowSecurityUser = (ShadowSecurityUser)list.get(0);	
        }
        
        return shadowSecurityUser;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllSecurityGroupsForUser(com.compuware.frameworks.security.service.api.model.AbstractUser, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
	public Collection<SecurityGroup> getSecurityGroupsForUser(
       AbstractUser user, 
       MultiTenancyRealm multiTenancyRealm)
    throws
       ObjectNotFoundException {
		
		Collection<SecurityGroup> securityGroups = new ArrayList<SecurityGroup>();
		
        Iterator<SecurityGroup> iterator = this.getAllSecurityGroups(multiTenancyRealm).iterator();
        while (iterator.hasNext()) {
            
        	SecurityGroup securityGroup = iterator.next();
        	if (securityGroup.getMemberUsers().contains(user)) {
        	    
        		securityGroups.add(securityGroup);
        	}
        }
        
        return securityGroups;
	}
    
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getSecurityGroupByGroupname(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
    public SecurityGroup getSecurityGroupByGroupname(
       String groupname, 
       MultiTenancyRealm multiTenancyRealm)
    throws
       ObjectNotFoundException {
    	
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_GROUP + " securityGroup where lower(securityGroup.principalName)=? and securityGroup.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSecurityPrincipal")    	
    	.setParameter(0, groupname.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        SecurityGroup securityGroup = null;
        if (list != null && list.size() == 1) {
        	securityGroup = (SecurityGroup)list.get(0);	
        } else if (list.size() == 0) {
        	throw new ObjectNotFoundException("Cannot find group with groupname: [" + groupname + "].");
        } else {
        	throw new IllegalStateException("There exists: [" + list.size()+ "] groups with groupname: [" + groupname + "] in realm: [" + multiTenancyRealm + "] and this should not be as both together should be unique.");
        }
        
        return securityGroup;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getShadowSecurityGroupByGroupname(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public ShadowSecurityGroup getShadowSecurityGroupByGroupname(
       String groupname, 
       MultiTenancyRealm multiTenancyRealm) {
    	
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SHADOW_SECURITY_GROUP + " shadowSecurityGroup where lower(shadowSecurityGroup.principalName)=? and shadowSecurityGroup.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getSecurityPrincipal")    	
    	.setParameter(0, groupname.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        ShadowSecurityGroup shadowSecurityGroup = null;
        if (list != null && list.size() == 1) {
        	shadowSecurityGroup = (ShadowSecurityGroup)list.get(0);	
        }
        
        return shadowSecurityGroup;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getGroupByGroupname(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public AbstractGroup getGroupByGroupname(
       String groupname, 
       MultiTenancyRealm multiTenancyRealm)
    throws
       ObjectNotFoundException {
    	
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + ABSTRACT_GROUP + " abstractGroup where lower(abstractGroup.principalName)=? and abstractGroup.multiTenancyRealm=?")
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAbstractGroup")    	
    	.setParameter(0, groupname.toLowerCase())
    	.setParameter(1, multiTenancyRealm)
    	.list();
    	
        AbstractGroup abstractGroup = null;
        if (list != null && list.size() == 1) {
        	abstractGroup = (AbstractGroup)list.get(0);	
        } else if (list.size() == 0) {
        	throw new ObjectNotFoundException("Cannot find group with groupname: [" + groupname + "].");
        } else {
        	throw new IllegalStateException("There exists: [" + list.size()+ "] groups with groupname: [" + groupname + "] in realm: [" + multiTenancyRealm + "] and this should not be as both together should be unique.");
        }
        
        return abstractGroup;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllSecurityUsersByCriteria(java.lang.String, java.lang.String, java.lang.String, java.lang.Boolean, boolean, int, int, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
	public Collection<SecurityUser> getAllSecurityUsersByCriteria(
		String firstNameCriteria,
		String lastNameCriteria,
		String primaryEmailAddressCriteria,
		Boolean isActiveCriteria,
		boolean isOrQuery,
		int firstResult,
		int maxResults,
		MultiTenancyRealm multiTenancyRealm) throws ValidationException {

	    validateFirstResultAndMaxResults(firstResult, maxResults);
		
		Criteria criteria = this.sessionFactory.getCurrentSession().createCriteria(SecurityUser.class);
		criteria.setFirstResult(firstResult);
		criteria.setMaxResults(maxResults);
		criteria.setCacheable(true);
		criteria.setFetchMode("passwords", FetchMode.SELECT);
		
		Set<Criterion> criteriaMap = new HashSet<Criterion>();
		
		if (firstNameCriteria != null && !firstNameCriteria.isEmpty()) {
			if (firstNameCriteria.length() > 256) {
				throw new ValidationException(ValidationException.FIELD_FIRST_NAME, ValidationException.REASON_CANNOT_BE_GREATER_THAN_256_CHARS);
			}
			Criterion criterion = Restrictions.ilike("firstName", OPERATOR_LIKE + firstNameCriteria + OPERATOR_LIKE);
			criteriaMap.add(criterion);
		}

		if (lastNameCriteria != null && !lastNameCriteria.isEmpty()) {
			if (lastNameCriteria.length() > 256) {
			    throw new ValidationException(ValidationException.FIELD_LAST_NAME, ValidationException.REASON_CANNOT_BE_GREATER_THAN_256_CHARS);
			}			
			Criterion criterion = Restrictions.ilike("lastName", "%" + lastNameCriteria + "%");
			criteriaMap.add(criterion);
		}
		
		if (primaryEmailAddressCriteria != null && !primaryEmailAddressCriteria.isEmpty()) {
			if (primaryEmailAddressCriteria.length() > 256) {
			    throw new ValidationException(ValidationException.FIELD_EMAIL_ADDRESS, ValidationException.REASON_CANNOT_BE_GREATER_THAN_256_CHARS);
			}			
			Criterion criterion = Restrictions.ilike("primaryEmailAddress", "%" + primaryEmailAddressCriteria + "%");
			criteriaMap.add(criterion);
		}
		
		Criterion leftCriterion = null;
		int criteriaMapSize = criteriaMap.size();
		if (criteriaMapSize == 0 && isActiveCriteria == null) {
			throw new ValidationException(ValidationException.FIELD_ALL, ValidationException.REASON_AT_LEAST_ONE_SEARCH_CRITERIA_MUST_BE_SPECIFIED);
		}

		if (criteriaMapSize > 0) {
    		Criterion[] criterionArray = criteriaMap.toArray(new Criterion[criteriaMapSize]);
    		leftCriterion = criterionArray[0];			
    		if (criterionArray.length > 1) {
    			for (int i=1; i < criterionArray.length; i++) {
    				Criterion rightCriterion = criterionArray[i];
    				Criterion criterion = null;
    				if (isOrQuery) {
    		    		criterion = Restrictions.or(leftCriterion, rightCriterion);
    		    	} else {
    		    		criterion = Restrictions.and(leftCriterion, rightCriterion);
    				}
    	    		leftCriterion = criterion;					
    			}
    		}
    		criteria.add(leftCriterion);
		}
		
        if (isActiveCriteria != null) {
            if (criteriaMapSize == 0) {
                if (isActiveCriteria.booleanValue()) {
                    leftCriterion = Restrictions.eq("isAccountLocked", Boolean.FALSE);    
                } else {
                    leftCriterion = Restrictions.eq("isAccountLocked", Boolean.TRUE);
                }
            } else {
                if (isActiveCriteria.booleanValue()) {
                    criteria.add(Restrictions.and(leftCriterion, Restrictions.eq("isAccountLocked", Boolean.FALSE)));    
                } else {
                    criteria.add(Restrictions.and(leftCriterion, Restrictions.eq("isAccountLocked", Boolean.TRUE)));
                }
            }
        }
		
        criteria.add(Restrictions.and(leftCriterion, Restrictions.eq(CRITERIA_MULTI_TENANCY_REALM, multiTenancyRealm)));
		
		@SuppressWarnings(RAW_TYPES)
		List list = criteria.list();
		
		Set<SecurityUser> set = new HashSet<SecurityUser>();
        int size = list.size();
        if (list != null && size > 0) {
        	for (int i=0; i < size; i++) {
        		SecurityUser securityUser = (SecurityUser)list.get(i);
        		set.add(securityUser);
        	}
        }
        
        List<SecurityUser> securityUsers = new ArrayList<SecurityUser>();
        Iterator<SecurityUser> iterator = set.iterator();
        while (iterator.hasNext()) {
            securityUsers.add(iterator.next());
        }
        Collections.sort(securityUsers, new SecurityPrincipalComparator());
        
        return securityUsers;
	}
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllSecurityUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
	public Collection<SecurityUser> getAllSecurityUsers(MultiTenancyRealm multiTenancyRealm) {
		
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_USER + " securityUser where securityUser.multiTenancyRealm=? order by securityUser.principalName")
    	.setParameter(0, multiTenancyRealm)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllSecurityUsers")    	    	
    	.list();
    	
        Collection<SecurityUser> securityUsers = new ArrayList<SecurityUser>();
        int size = list.size();
        if (list != null && size > 0) {
        	for (int i=0; i < size; i++) {
        		SecurityUser securityUser = (SecurityUser)list.get(i);
        		securityUsers.add(securityUser);
        	}
        }
        
        return securityUsers;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllActiveSecurityUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityUser> getAllActiveSecurityUsers(MultiTenancyRealm multiTenancyRealm) {

        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_USER + " securityUser where securityUser.multiTenancyRealm=? and securityUser.isAccountLocked=? order by securityUser.principalName")
    	.setParameter(0, multiTenancyRealm)
    	.setParameter(1, false)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllActiveSecurityUsers")    	    	
    	.list();
    	
        Collection<SecurityUser> securityUsers = new ArrayList<SecurityUser>();
        int size = list.size();
        if (list != null && size > 0) {
        	for (int i=0; i < size; i++) {
        		SecurityUser securityUser = (SecurityUser)list.get(i);
        		securityUsers.add(securityUser);
        	}
        }
        
        return securityUsers;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllInactiveSecurityUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityUser> getAllInactiveSecurityUsers(MultiTenancyRealm multiTenancyRealm) {

        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_USER + " securityUser where securityUser.multiTenancyRealm=? and securityUser.isAccountLocked=? order by securityUser.principalName")
    	.setParameter(0, multiTenancyRealm)
    	.setParameter(1, true)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllInactiveSecurityUsers")    	    	
    	.list();
    	
        Collection<SecurityUser> securityUsers = new ArrayList<SecurityUser>();
        int size = list.size();
        if (list != null && size > 0) {
        	for (int i=0; i < size; i++) {
        		SecurityUser securityUser = (SecurityUser)list.get(i);
        		securityUsers.add(securityUser);
        	}
        }
        
        return securityUsers;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllSystemUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SystemUser> getAllSystemUsers(MultiTenancyRealm multiTenancyRealm) {
		
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SYSTEM_USER + " systemUser where systemUser.multiTenancyRealm=? order by systemUser.principalName")
    	.setParameter(0, multiTenancyRealm)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllSystemUsers")    	    	
    	.list();
    	
        Collection<SystemUser> systemUsers = new ArrayList<SystemUser>();
        int size = list.size();
        if (list != null && size > 0) {
        	for (int i=0; i < size; i++) {
        		SystemUser systemUser = (SystemUser)list.get(i);
        		systemUsers.add(systemUser);
        	}
        }
        
        return systemUsers;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllUsers(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<AbstractUser> getAllUsers(MultiTenancyRealm multiTenancyRealm) {
		
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + ABSTRACT_USER + " abstractUser where abstractUser.multiTenancyRealm=? order by abstractUser.principalName")
    	.setParameter(0, multiTenancyRealm)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllUsers")    	    	
    	.list();
    	
        Collection<AbstractUser> abstractUsers = new ArrayList<AbstractUser>();
        int size = list.size();
        if (list != null && size > 0) {
        	for (int i=0; i < size; i++) {
        		AbstractUser abstractUser = (AbstractUser)list.get(i);
        		abstractUsers.add(abstractUser);
        	}
        }
        
        return abstractUsers;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllSecurityGroups(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityGroup> getAllSecurityGroups(MultiTenancyRealm multiTenancyRealm) {
		
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + SECURITY_GROUP + " securityGroup where securityGroup.multiTenancyRealm=? order by securityGroup.principalName")
    	.setParameter(0, multiTenancyRealm)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllSecurityGroups")    	    	
    	.list();
    	
        Collection<SecurityGroup> securityGroups = new ArrayList<SecurityGroup>();
        int size = list.size();
        if (list != null && size > 0) {
        	for (int i=0; i < size; i++) {
        		SecurityGroup securityGroup = (SecurityGroup)list.get(i);
        		securityGroups.add(securityGroup);
        	}
        }
        
        return securityGroups;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllDefaultSecurityGroups(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<SecurityGroup> getAllDefaultSecurityGroups(MultiTenancyRealm multiTenancyRealm) {

        @SuppressWarnings(RAW_TYPES)
        List list = this.sessionFactory.getCurrentSession()
        .createQuery(FROM + SECURITY_GROUP + " securityGroup where securityGroup.multiTenancyRealm=? and securityGroup.assignByDefault=? order by securityGroup.principalName")
        .setParameter(0, multiTenancyRealm)
        .setParameter(1, true)
        .setCacheable(true)
        .setCacheRegion("com.compuware.frameworks.security.persistence.getAllSecurityGroups")               
        .list();
        
        Collection<SecurityGroup> securityGroups = new ArrayList<SecurityGroup>();
        int size = list.size();
        if (list != null && size > 0) {
            for (int i=0; i < size; i++) {
                SecurityGroup securityGroup = (SecurityGroup)list.get(i);
                securityGroups.add(securityGroup);
            }
        }
        
        return securityGroups;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllGroups(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<AbstractGroup> getAllGroups(MultiTenancyRealm multiTenancyRealm) {
		
        @SuppressWarnings(RAW_TYPES)
		List list = this.sessionFactory.getCurrentSession()
    	.createQuery(FROM + ABSTRACT_GROUP + " abstractGroup where abstractGroup.multiTenancyRealm=? order by abstractGroup.principalName")
    	.setParameter(0, multiTenancyRealm)
    	.setCacheable(true)
    	.setCacheRegion("com.compuware.frameworks.security.persistence.getAllGroups")    	    	
    	.list();
    	
        Collection<AbstractGroup> abstractGroups = new ArrayList<AbstractGroup>();
        int size = list.size();
        if (list != null && size > 0) {
        	for (int i=0; i < size; i++) {
        		AbstractGroup abstractGroup = (AbstractGroup)list.get(i);
        		abstractGroups.add(abstractGroup);
        	}
        }
        
        return abstractGroups;
	}
	
	public SecurityUser createSecurityUser(SecurityUser securityUser)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException,
	   PasswordPolicyException {
		
		if (securityPrincipalExists(securityUser.getUsername(), securityUser.getMultiTenancyRealm())) {
			throw new ObjectAlreadyExistsException("Security Principal: [" + securityUser + "] already exists in realm: [" + securityUser.getMultiTenancyRealm() + "].");
		}
				
		this.sessionFactory.getCurrentSession().save(securityUser);
				
		return securityUser;
	}

    public SystemUser createSystemUser(SystemUser systemUser)
    throws
       ObjectAlreadyExistsException,
       ValidationException {
        
        if (securityPrincipalExists(systemUser.getUsername(), systemUser.getMultiTenancyRealm())) {
            throw new ObjectAlreadyExistsException("Security Principal: [" + systemUser + "] already exists in realm: [" + systemUser.getMultiTenancyRealm() + "].");
        }
                
        this.sessionFactory.getCurrentSession().save(systemUser);
        
        return systemUser;
    }
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#createShadowSecurityUser(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public ShadowSecurityUser createShadowSecurityUser(
	   String username,
	   MultiTenancyRealm multiTenancyRealm)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException {
		
		if (securityPrincipalExists(username, multiTenancyRealm)) {
			throw new ObjectAlreadyExistsException("Security Principal: [" + username + "] already exists in realm: [" + multiTenancyRealm + "].");
		}
				
		ShadowSecurityUser shadowSecurityUser = new DomainObjectFactory().createShadowSecurityUser(
			username, 
			multiTenancyRealm);
				
		this.sessionFactory.getCurrentSession().save(shadowSecurityUser);
		
		return shadowSecurityUser;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#createSecurityGroup(java.lang.String, java.lang.String, boolean, boolean, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public SecurityGroup createSecurityGroup(
	   String groupname,
	   String description,
	   boolean assignByDefault,
       boolean isDeletable,
       boolean isModifiable,       	   
	   MultiTenancyRealm multiTenancyRealm)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException {
	   SecurityGroup parentGroup = null;
	   return createSecurityGroup(
	       groupname,
	       description,
	       assignByDefault,
	       parentGroup,
	       isDeletable,
	       isModifiable,
	       multiTenancyRealm);
	}	

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#createSecurityGroup(java.lang.String, java.lang.String, boolean, com.compuware.frameworks.security.service.api.model.SecurityGroup, boolean, boolean, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public SecurityGroup createSecurityGroup(
	   String groupname,
	   String description,
	   boolean assignByDefault,
	   SecurityGroup parentGroup,
       boolean isDeletable,
       boolean isModifiable,       	   
	   MultiTenancyRealm multiTenancyRealm)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException {
		
		if (securityPrincipalExists(groupname, multiTenancyRealm)) {
			throw new ObjectAlreadyExistsException("Security Principal: [" + groupname + "] already exists in realm: [" + multiTenancyRealm + "].");
		}
		
        Set<AbstractUser> memberUsers = new TreeSet<AbstractUser>();		
		SecurityGroup securityGroup = new DomainObjectFactory().createSecurityGroup(
			groupname, 
			description,
            assignByDefault,
            memberUsers,
            parentGroup,
            isDeletable,
            isModifiable,               
			multiTenancyRealm);
				
		this.sessionFactory.getCurrentSession().save(securityGroup);
		
		return securityGroup;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#createShadowSecurityGroup(java.lang.String, java.lang.String, java.util.Set, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public ShadowSecurityGroup createShadowSecurityGroup(
	   String groupname,
	   MultiTenancyRealm multiTenancyRealm)
	throws
	   ObjectAlreadyExistsException,
	   ValidationException {

		if (securityPrincipalExists(groupname, multiTenancyRealm)) {
			throw new ObjectAlreadyExistsException("Security Principal: [" + groupname + "] already exists in realm: [" + multiTenancyRealm + "].");
		}
		
		ShadowSecurityGroup shadowSecurityGroup = new DomainObjectFactory().createShadowSecurityGroup(
				groupname, 
				multiTenancyRealm);
				
		this.sessionFactory.getCurrentSession().save(shadowSecurityGroup);
		
		return shadowSecurityGroup;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao#getAllGroupsByCriteria(java.lang.String, int, int, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	public Collection<AbstractGroup> getAllGroupsByCriteria(
	    String groupnameCriteria,
        int firstResult,
        int maxResults,
        MultiTenancyRealm multiTenancyRealm) 
    throws
        ValidationException {
	    	   
	    validateFirstResultAndMaxResults(firstResult, maxResults);
        
        Criteria criteria = this.sessionFactory.getCurrentSession().createCriteria(AbstractGroup.class);
        criteria.setFirstResult(firstResult);
        criteria.setMaxResults(maxResults);
        criteria.setCacheable(true);
        criteria.setFetchMode("memberUsers", FetchMode.SELECT);
        
        if (groupnameCriteria.length() > 256) {
            throw new ValidationException(ValidationException.FIELD_GROUP_NAME, ValidationException.REASON_CANNOT_BE_GREATER_THAN_256_CHARS);
        }
        Criterion groupnameCriterion = Restrictions.ilike("principalName", OPERATOR_LIKE + groupnameCriteria + OPERATOR_LIKE);
        
        criteria.add(Restrictions.and(groupnameCriterion, Restrictions.eq(CRITERIA_MULTI_TENANCY_REALM, multiTenancyRealm)));
        
        @SuppressWarnings(RAW_TYPES)
        List list = criteria.list();
        
        Set<AbstractGroup> set = new HashSet<AbstractGroup>();
        int size = list.size();
        if (list != null && size > 0) {
            for (int i=0; i < size; i++) {
                AbstractGroup abstractGroup = (AbstractGroup)list.get(i);
                set.add(abstractGroup);
            }
        }
        
        List<AbstractGroup> allGroupsByCriteria = new ArrayList<AbstractGroup>();
        Iterator<AbstractGroup> iterator = set.iterator();
        while (iterator.hasNext()) {
            allGroupsByCriteria.add(iterator.next());
        }
        Collections.sort(allGroupsByCriteria, new SecurityPrincipalComparator());
        
        return allGroupsByCriteria;
	}

	/*
	 * 
	 * @param firstResult
	 * @param maxResults
	 * @throws ValidationException
	 */
	private void validateFirstResultAndMaxResults(int firstResult, int maxResults) throws ValidationException {
	    
	    if (firstResult < 0) {
	        throw new ValidationException(ValidationException.FIELD_FIRST_RESULT, ValidationException.REASON_CANNOT_BE_NEGATIVE);
	    }
	    
	    if (maxResults < 1) {
	        throw new ValidationException(ValidationException.FIELD_MAX_RESULTS, ValidationException.REASON_MUST_BE_POSITIVE_NONZERO_NUMBER);
	    }       
	}
}