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
package com.compuware.frameworks.security.service.server.audit;

import java.util.List;

import com.compuware.frameworks.security.persistence.dao.IAuditEventDao;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.model.AuditEvent;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public final class AuditServiceImpl implements IAuditService {

	/** */
	private IAuditEventDao auditEventDao;

	/**
	 * 
	 */
	public AuditServiceImpl() {
	}
	
	/**
	 * 
	 * @param auditEventDao
	 */
	public AuditServiceImpl(IAuditEventDao auditEventDao) {
		setAuditEventDao(auditEventDao);
	}
	
	/**
	 * @param auditEventDao the auditEventDao to set
	 */
	public void setAuditEventDao(IAuditEventDao auditEventDao) {
		this.auditEventDao = auditEventDao;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.audit.IAuditService#createAuditEvent(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public AuditEvent createAuditEvent(
	   String initiatingUsername,
	   String eventDetails,
	   String originatingIpAddress,
	   String originatingHostname,
	   String realmName) 
	throws 
	   ObjectAlreadyExistsException,
	   ValidationException {
		
		return this.auditEventDao.createAuditEvent(
				initiatingUsername, 
				eventDetails, 
				originatingIpAddress, 
				originatingHostname, 
				realmName);
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.audit.IAuditService#getAllAuditEvents(java.util.Date, java.util.Date, java.lang.String)
	 */
	public List<AuditEvent> getAllAuditEvents(
			java.util.Date fromDate,
			java.util.Date toDate,
			String realmName) {
	            
		return this.auditEventDao.getAllAuditEvents(
			fromDate, 
			toDate,
			realmName);
	}
}