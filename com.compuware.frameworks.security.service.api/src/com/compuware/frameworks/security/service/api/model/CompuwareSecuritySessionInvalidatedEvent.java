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
package com.compuware.frameworks.security.service.api.model;

import javax.xml.bind.annotation.XmlRootElement;


/**
 * This event can be fired explicitly upon logout by the user, or implicitly, 
 * through either excedding the session inactivity or max. session life thresholds. 
 * 
 * @author tmyers
 *
 */
@XmlRootElement
public final class CompuwareSecuritySessionInvalidatedEvent extends CompuwareSecuritySessionEvent {

    /** */
    private static final long serialVersionUID = 1L;
    
    /**
     * 
     */
    protected CompuwareSecuritySessionInvalidatedEvent() {
        super();
    }

    /**
     * @param sessionId
     * @param realmName
     */
    public CompuwareSecuritySessionInvalidatedEvent(
        String sessionId,
        String realmName) {
        
        super(
            sessionId,    
            realmName);
    }
}