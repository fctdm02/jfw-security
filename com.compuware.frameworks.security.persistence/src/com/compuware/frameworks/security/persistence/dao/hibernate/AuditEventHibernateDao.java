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

import java.util.List;

import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;

import com.compuware.frameworks.security.persistence.dao.IAuditEventDao;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.model.AuditEvent;
import com.compuware.frameworks.security.service.api.model.DomainObjectFactory;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public final class AuditEventHibernateDao extends BaseHibernateDao implements IAuditEventDao {
    
    /* */
    private final Logger logger = Logger.getLogger(AuditEventHibernateDao.class);

    /**
     * 
     * @param sessionFactory
     */
    public AuditEventHibernateDao(SessionFactory sessionFactory) {
    	super(sessionFactory);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IAuditEventDao#auditEventExists(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public boolean auditEventExists(
        String initiatingUsername,
        String eventDetails,
        String originatingIpAddress,
        String originatingHostname,
        java.util.Date eventDate,
        String realmName) {
        
        @SuppressWarnings(RAW_TYPES)
        List list = this.sessionFactory.getCurrentSession()
        .createQuery(FROM + AUDIT_EVENT + " auditEvent where auditEvent.initiatingUsername=? and auditEvent.eventDetails=? and auditEvent.originatingIpAddress=? and auditEvent.originatingHostname=? and auditEvent.eventDate=? and auditEvent.realmName=?")
        .setCacheable(false)
        .setParameter(0, initiatingUsername)
        .setParameter(1, eventDetails)
        .setParameter(2, originatingIpAddress)
        .setParameter(3, originatingHostname)
        .setParameter(4, eventDate)
        .setParameter(5, realmName)
        .list();
        
        if (list.size() == 0) {
            return false;
        }
        return true;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IAuditEventDao#createAuditEvent(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
	public AuditEvent createAuditEvent(
	    String initiatingUsername,
	    final String eventDetails,
	    String originatingIpAddress,
	    String originatingHostname,
	    String realmName)
	throws 
	    ObjectAlreadyExistsException, 
	    ValidationException {

		long currentTimeMillis = System.currentTimeMillis();
		AuditEvent auditEvent = null;
		java.util.Date eventDate = null;
		

		
		// This should only happen during the unit tests, but see if the time offset system property has been set.  
		// This would have the effect of making the audit event older than it should be.
		long systemCurrentTimeMillisOffset = 0;
		String systemCurrentTimeMillisOffsetProperty = System.getProperty("systemCurrentTimeMillisOffset");
		if (systemCurrentTimeMillisOffsetProperty != null) {
		    systemCurrentTimeMillisOffset = Long.parseLong(systemCurrentTimeMillisOffsetProperty);
		    eventDate = new java.util.Date(currentTimeMillis - systemCurrentTimeMillisOffset);
		    logger.debug("Using Audit Event systemCurrentTimeMillisOffset: " + systemCurrentTimeMillisOffset + ", eventDate: " + eventDate);
		} else {
		    eventDate = new java.util.Date(currentTimeMillis);
		}

		
		
        auditEvent = new DomainObjectFactory().createAuditEvent(
                initiatingUsername, 
                eventDetails, 
                originatingIpAddress, 
                originatingHostname, 
                eventDate,
                realmName);
		
		if (!auditEventExists(initiatingUsername, eventDetails, originatingIpAddress, originatingHostname, eventDate, realmName)) {
	        logger.debug("Creating audit event: " + auditEvent);
	        this.sessionFactory.getCurrentSession().save(auditEvent);
		} else {
		    logger.error("Could not create audit event: [" + auditEvent.getNaturalIdentity() + "] because one already exists with the same identity.");
		}
		        
		return auditEvent;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.IAuditEventDao#getAllAuditEvents(java.util.Date, java.util.Date, java.lang.String)
	 */
	@SuppressWarnings("unchecked")
	public List<AuditEvent> getAllAuditEvents(
		java.util.Date fromDate,
		java.util.Date toDate,
		String realmName) {
	    
        if (realmName == null) {
            throw new IllegalStateException("'realmName' cannot be null, please specify one and try again.");
        }

	    if (fromDate != null && toDate != null) {
	        
	        return this.sessionFactory.getCurrentSession()
	        .createQuery(FROM + AUDIT_EVENT + " auditEvent where auditEvent.realmName=? and auditEvent.eventDate >= ? and auditEvent.eventDate <= ?")
	        .setParameter(0, realmName)
	        .setParameter(1, fromDate)
	        .setParameter(2, toDate)
	        .setCacheable(false)
	        .setMaxResults(MAX_RESULTS)
	        .list();
	        
	    } else if (fromDate != null && toDate == null) {
	        
	        return this.sessionFactory.getCurrentSession()
	        .createQuery(FROM + AUDIT_EVENT + " auditEvent where auditEvent.realmName=? and auditEvent.eventDate >= ?")
	        .setParameter(0, realmName)
            .setParameter(1, fromDate)	        
	        .setCacheable(false)
            .setMaxResults(MAX_RESULTS)
	        .list();
	        
	    } else if (fromDate == null && toDate != null) {
	        
	        return this.sessionFactory.getCurrentSession()
	        .createQuery(FROM + AUDIT_EVENT + " auditEvent where auditEvent.realmName=? and auditEvent.eventDate <= ?")
	        .setParameter(0, realmName)
	        .setParameter(1, toDate)
	        .setCacheable(false)
            .setMaxResults(MAX_RESULTS)
	        .list();
	        
	    } else {
	        
            return this.sessionFactory.getCurrentSession()
            .createQuery(FROM + AUDIT_EVENT + " auditEvent where auditEvent.realmName=?")
            .setParameter(0, realmName)
            .setCacheable(false)
            .setMaxResults(MAX_RESULTS)
            .list();
	    }
	}
}