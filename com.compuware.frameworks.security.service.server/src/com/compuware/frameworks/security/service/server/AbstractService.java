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
package com.compuware.frameworks.security.service.server;

import java.util.Iterator;

import org.apache.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventListener;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventProducer;
import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.model.AbstractUser;
import com.compuware.frameworks.security.service.api.model.AuditEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityUserInitiatedEvent;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;


/**
 * @author tmyers
 */
public abstract class AbstractService implements ICompuwareSecurityEventProducer {

    /* */
    private final Logger logger = Logger.getLogger(AbstractService.class);

	/** */
	private IAuditService auditService;
	
	/** */
	private IEventService eventService;	
	
	/** */
	private IMultiTenancyRealmDao multiTenancyRealmDao;

	/**
	 * 
	 * @param auditService
	 * @param eventService
	 * @param multiTenancyRealmDao
	 */
	public AbstractService(
		IAuditService auditService,
		IEventService eventService,
		IMultiTenancyRealmDao multiTenancyRealmDao) {
		setAuditService(auditService);
		setEventService(eventService);
		setMultiTenancyRealmDao(multiTenancyRealmDao);
	}

	/**
	 * 
	 * @param auditService the auditService to set
	 */
	public final void setAuditService(IAuditService auditService) {
		this.auditService = auditService;
	}

	/**
	 * 
	 * @param eventService the eventService to set
	 */
	public final void setEventService(IEventService eventService) {
		this.eventService = eventService;
	}
	
	/**
	 * 
	 * @return
	 */
	public final IEventService getEventService() {
	    return this.eventService;
	}
	
	/**
	 * 
	 * @param multiTenancyRealmDao the multiTenancyRealmDao to set
	 */
	public final void setMultiTenancyRealmDao(IMultiTenancyRealmDao multiTenancyRealmDao) {
		this.multiTenancyRealmDao = multiTenancyRealmDao;
	}
	
	/**
	 * 
	 * @return
	 */
	protected final IMultiTenancyRealmDao getMultiTenancyRealmDao() {
		return this.multiTenancyRealmDao;
	}

	/**
	 * @return 
	 */
	protected final MultiTenancyRealm getMultiTenancyRealmForSecurityContext() {
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new ServiceException("Authentication not set in SecurityContext.");
		}
		
		CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken = null;
		if (!(authentication instanceof CompuwareSecurityAuthenticationToken)) {
			throw new ServiceException("Authentication is not an instance of CompuwareSecurityAuthenticationToken.");
		}
		compuwareSecurityAuthenticationToken = (CompuwareSecurityAuthenticationToken)authentication;
		
		AbstractUser abstractUser = compuwareSecurityAuthenticationToken.getUserObject();
		MultiTenancyRealm multiTenancyRealm = abstractUser.getMultiTenancyRealm();
		return multiTenancyRealm;
	}

	/**
	 * 
	 * @return
	 */
	protected final CompuwareSecurityAuthenticationToken getCurrentAuthenticationContext() {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new ServiceException("Authentication not set in SecurityContext.");
		}
		
		if (!(authentication instanceof CompuwareSecurityAuthenticationToken)) {
			throw new ServiceException("Authentication is not an instance of CompuwareSecurityAuthenticationToken.");
		}
		
		return (CompuwareSecurityAuthenticationToken)authentication;
	}

    /**
     * 
     * @return
     */
    protected final AbstractUser getCurrentlyAuthenticatedUser() {

        CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken = getCurrentAuthenticationContext();
        return compuwareSecurityAuthenticationToken.getUserObject();
    }
					
	/**
	 * 
	 * @param initiatingUsername
	 * @param eventDetails
	 * @param originatingIpAddress
	 * @param originatingHostname
	 * @param realmName
	 */
	protected final void createAuditEvent(CompuwareSecurityEvent compuwareSecurityEvent) {
			    
	    // We only want to create an audit event that will be stored in the 
	    // database for a user-initiated event.
	    java.util.Date eventDate = null;
	    if (compuwareSecurityEvent instanceof CompuwareSecurityUserInitiatedEvent) {
	        AuditEvent auditEvent = null;
	        try {
	            auditEvent = auditService.createAuditEvent(
	                ((CompuwareSecurityUserInitiatedEvent)compuwareSecurityEvent).getInitiatingUsername(),
	                compuwareSecurityEvent.getEventDetails(),
	                ((CompuwareSecurityUserInitiatedEvent)compuwareSecurityEvent).getOriginatingIpAddress(),
	                ((CompuwareSecurityUserInitiatedEvent)compuwareSecurityEvent).getOriginatingHostname(),
	                compuwareSecurityEvent.getRealmName());
	            eventDate = auditEvent.getEventDate();
	        } catch (Exception e) {
	            logger.error("Could not create audit event:[" + auditEvent +"], error: " + e.getMessage(), e);
	        }
	    }
		
		long eventAge = 0;
		if (eventDate == null) {
		    eventAge = System.currentTimeMillis();
		    eventDate = new java.util.Date(eventAge);
		} else {
		    eventAge = eventDate.getTime();
		}
		
		
		// Notify any listeners.  It is their choice as to whether or not they act upon any of them. 
		// All they need to do is look for the appropriate event sub class.
		fireCompuwareSecurityEvent(compuwareSecurityEvent);
		
		
		// Lastly, log the event as well. 
		logger.debug(compuwareSecurityEvent);
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.server.event.IServiceEventProducer#fireCompuwareSecurityEvent(com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent)
	 */
    public final void fireCompuwareSecurityEvent(CompuwareSecurityEvent compuwareSecurityEvent) {
        
        String realmName = compuwareSecurityEvent.getRealmName();
    	Iterator<ICompuwareSecurityEventListener> iterator = this.eventService.getCompuwareSecurityEventListeners(realmName).iterator();
    	while (iterator.hasNext()) {
    		
    		ICompuwareSecurityEventListener compuwareSecurityEventListener = iterator.next();
    		compuwareSecurityEventListener.compuwareSecurityEventOccurred(compuwareSecurityEvent);
    	}
    	
    	// This is a "backup" way of getting events  
        // (i.e. via direct polling from the client).  This method
        // was added to mitigate the risk involving the messaging
        // infrastructure.
    	this.eventService.fireCompuwareSecurityEvent(compuwareSecurityEvent);
    }	
}