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
package com.compuware.frameworks.security.service.api.model;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;


/**
 * 
 * @author tmyers
 *
 */
@XmlRootElement
@XmlSeeAlso({CompuwareSecurityConfigurationChangedEvent.class,CompuwareSecuritySaveConfigurationErrorEvent.class})
public abstract class CompuwareSecurityConfigurationEvent extends CompuwareSecurityUserInitiatedEvent {

    /* */
    private static final long serialVersionUID = 1L;
    
    /**
     * 
     */
    protected CompuwareSecurityConfigurationEvent() {
        super();
    }
    
    /**
     * @param initiatingUsername
     * @param originatingIpAddress
     * @param originatingHostname
     * @param eventDetails
     * @param realmName
     */
    public CompuwareSecurityConfigurationEvent(
        String initiatingUsername,
        String originatingIpAddress,
        String originatingHostname,
        String eventDetails,
        String realmName) {
        
        super(
            initiatingUsername,
            originatingIpAddress,
            originatingHostname,
            eventDetails,
            realmName);
    }
}