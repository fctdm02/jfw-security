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
package com.compuware.frameworks.security.service.api.event;

import com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent;

/**
 * 
 * @author tmyers
 *
 */
public interface ICompuwareSecurityEventListener {

	/**
	 * Invoked when a compuware security event occurs. 
	 * The implementing method can according according to the 
	 * type/details of the passed in event. 
	 * 
	 * @param compuwareSecurityEvent The Compuware Security Event that occurred.
	 */
	void compuwareSecurityEventOccurred(CompuwareSecurityEvent compuwareSecurityEvent);
}