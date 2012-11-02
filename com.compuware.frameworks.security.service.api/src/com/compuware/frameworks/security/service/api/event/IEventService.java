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

import java.util.List;

import com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent;

/**
 * 
 * @author tmyers
 *
 */
public interface IEventService {
		
    /**
     * Registers a listener to be notified whenever an event has occurred
     * for the given realm.
     * 
     * @param compuwareSecurityEventListener
     * @param realmName
     */
    void addCompuwareSecurityEventListener(
        ICompuwareSecurityEventListener compuwareSecurityEventListener,
        String realmName);
    
    /**
     * @param realmName
     * @return The list of listeners for the given realm.
     */
    List<ICompuwareSecurityEventListener> getCompuwareSecurityEventListeners(String realmName);

    /**
     * Removes the specified event listener from the event listener list 
     * for the given realm.
     * 
     * @param compuwareSecurityEventListener
     * @param realmName
     */
    void removeCompuwareSecurityEventListener(
        ICompuwareSecurityEventListener compuwareSecurityEventListener,
        String realmName);
    
    /**
     * Removes all event listeners for the given realm.
     * 
     * @param realmName
     */
    void removeAllCompuwareSecurityEventListeners(String realmName);
    
    
    

    /**
     * TODO: TDM: This is a "backup" way of getting events 
     * (i.e. via direct polling from the client).  This method
     * was added to mitigate the risk involving the messaging
     * infrastructure.
     * 
     * @param compuwareSecurityEvent
     * @return
     */
    void fireCompuwareSecurityEvent(CompuwareSecurityEvent compuwareSecurityEvent);
    
    /**
     * TODO: TDM: This is a "backup" way of getting events 
     * (i.e. via direct polling from the client).  This method
     * was added to mitigate the risk involving the messaging
     * infrastructure.
     * 
     * @param ageThresholdMillis Since the java epoch
     * @param realmName
     * @return All events new than ageThreshold
     */
    List<CompuwareSecurityEvent> getRecentCompuwareSecurityEvents(
        long ageThresholdMillis, 
        String realmName);
}