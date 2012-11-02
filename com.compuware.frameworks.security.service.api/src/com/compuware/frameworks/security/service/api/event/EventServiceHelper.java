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
package com.compuware.frameworks.security.service.api.event;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;

/**
 * 
 * @author tmyers
 * 
 */
public class EventServiceHelper {
    
    /* */
    private final Logger logger = Logger.getLogger(EventServiceHelper.class);
    
    /* */
    private Set<ICompuwareSecurityEventListener> compuwareSecurityEventListeners;

    /**
     * 
     */
    public EventServiceHelper() {
        logger.debug("Creating event listener set.");
        this.compuwareSecurityEventListeners = new HashSet<ICompuwareSecurityEventListener>();        
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.client.api.IEventServiceClient#addHostApplicationSecurityEventListener(com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventListener)
     */
    public synchronized void addHostApplicationSecurityEventListener(ICompuwareSecurityEventListener compuwareSecurityEventListener) {
        this.compuwareSecurityEventListeners.add(compuwareSecurityEventListener);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.client.api.IEventServiceClient#getHostApplicationSecurityEventListeners()
     */
    public synchronized List<ICompuwareSecurityEventListener> getHostApplicationSecurityEventListeners() {
        List<ICompuwareSecurityEventListener> list = new ArrayList<ICompuwareSecurityEventListener>();
        list.addAll(this.compuwareSecurityEventListeners);
        return list;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.client.api.IEventServiceClient#removeHostApplicationSecurityEventListener(com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventListener)
     */
    public synchronized void removeHostApplicationSecurityEventListener(ICompuwareSecurityEventListener compuwareSecurityEventListener) {
        this.compuwareSecurityEventListeners.remove(compuwareSecurityEventListener);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.client.api.IEventServiceClient#removeAllHostApplicationCompuwareSecurityEventListeners()
     */
    public synchronized void removeAllHostApplicationCompuwareSecurityEventListeners() {
        this.compuwareSecurityEventListeners.clear();
    }    
}