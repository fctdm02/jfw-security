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
package com.compuware.frameworks.security.service.api.audit;

import java.util.List;

import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.model.AuditEvent;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;


/**
 * 
 * @author tmyers
 *
 */
public interface IAuditService {

	/**
	 * 
	 * @param initiatingUsername
	 * @param eventDetails
	 * @param originatingIpAddress
	 * @param originatingHostname
	 * @param realmName
	 * @return AuditEvent
	 * @throws ObjectAlreadyExistsException
	 * @throws ValidationException
	 */
	AuditEvent createAuditEvent(
	   String initiatingUsername,
	   String eventDetails,
	   String originatingIpAddress,
	   String originatingHostname,
	   String realmName)
	throws 
	    ObjectAlreadyExistsException,	
		ValidationException;

	/**
	 * 
     * @param fromDate If null, the oldest audit events are included. 
     * @param toDate If null, the newest audit events are included.
	 * @param realmName
	 * @return Collection<AuditEvent>
	 */
	List<AuditEvent> getAllAuditEvents(
		java.util.Date fromDate,
		java.util.Date toDate,
		String realmName);
}