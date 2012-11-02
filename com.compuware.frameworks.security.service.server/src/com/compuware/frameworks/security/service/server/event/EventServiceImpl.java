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
package com.compuware.frameworks.security.service.server.event;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.log4j.Logger;

import com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventListener;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent;

/**
 * 
 * @author tmyers
 *
 */
public final class EventServiceImpl implements IEventService {

    /* */
    private final Logger logger = Logger.getLogger(EventServiceImpl.class);
    
	/** The event listener map is keyed by realm name. */
	private Map<String, Set<ICompuwareSecurityEventListener>> compuwareSecurityEventListeners;
	
	/**
     * This is a "backup" way of getting events 
     * (i.e. via direct polling from the client).  This 
     * was added to mitigate the risk involving the messaging
     * infrastructure.
	 */
	private static final Map<String, List<CompuwareSecurityEvent>> COMPUWARE_SECURITY_EVENT_MAP  = new HashMap<String, List<CompuwareSecurityEvent>>();

	/**
     * This is a "backup" way of getting events 
     * (i.e. via direct polling from the client).  This 
     * was added to mitigate the risk involving the messaging
     * infrastructure.
     * <p>
     * We only want to hold 10 minutes worth of events for clients to retrieve via polling.
	 */
	private static final long MAX_AGE_MILLIS = 10 * 60 * 1000;
	
	/**
     * This is a "backup" way of getting events 
     * (i.e. via direct polling from the client).  This 
     * was added to mitigate the risk involving the messaging
     * infrastructure.
	 */
	private Timer timer;

    /**
     * This is a "backup" way of getting events 
     * (i.e. via direct polling from the client).  This 
     * was added to mitigate the risk involving the messaging
     * infrastructure.
     */
	private static final long DELAY = MAX_AGE_MILLIS;

    /**
     * This is a "backup" way of getting events 
     * (i.e. via direct polling from the client).  This 
     * was added to mitigate the risk involving the messaging
     * infrastructure.
     */
	private static final long PERIOD = MAX_AGE_MILLIS;
		
	/**
	 * 
	 */
	public EventServiceImpl() {
	    logger.debug("Creating event listener map.");
	    this.compuwareSecurityEventListeners = new HashMap<String, Set<ICompuwareSecurityEventListener>>();
	    
	    logger.debug("Creating event timer thread.");
	    this.timer = new Timer("Compuware Security Event Timer thread.");
	    timer.schedule(new TimerTask() {
	        
	        /*
	         * (non-Javadoc)
	         * @see java.util.TimerTask#run()
	         */
	        public void run() {
	            
	            // TODO: TDM: Look into blocking access to this map during this cleanup.
	            
	            // Purge old events for each realm.
	            List<CompuwareSecurityEvent> purgeList = new ArrayList<CompuwareSecurityEvent>();
	            Iterator<String> realmIterator = COMPUWARE_SECURITY_EVENT_MAP.keySet().iterator();
	            while (realmIterator.hasNext()) {
	                
	                String realmName = realmIterator.next();
	                if (logger.isDebugEnabled()) {
	                    logger.debug("Peforming maintenance on security event map for realm: " + realmName);
	                }
	                
	                List<CompuwareSecurityEvent> eventList = COMPUWARE_SECURITY_EVENT_MAP.get(realmName);
	                Iterator<CompuwareSecurityEvent> eventIterator = eventList.iterator();
	                while (eventIterator.hasNext()) {
	                    
	                    CompuwareSecurityEvent compuwareSecurityEvent = eventIterator.next();
	                    if (System.currentTimeMillis() - compuwareSecurityEvent.getEventAge() > MAX_AGE_MILLIS) {
	                        
	                        purgeList.add(compuwareSecurityEvent);
	                    }
	                }
	                
                    if (logger.isDebugEnabled()) {
                        logger.debug("Removing: [" + purgeList.size() + "] old events for realm: " + realmName);
                    }	                
	                eventList.removeAll(purgeList);
	            }
	        }
	        
	    }, DELAY, PERIOD);
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.event.IEventService#fireCompuwareSecurityEvent(com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent)
	 */
	public synchronized void fireCompuwareSecurityEvent(CompuwareSecurityEvent compuwareSecurityEvent) {

	    String realmName = compuwareSecurityEvent.getRealmName();
	    List<CompuwareSecurityEvent> recentServiceEventsList = getCompuwareSecurityEventList(realmName);
	    recentServiceEventsList.add(compuwareSecurityEvent);
	    
        StringBuilder sb = new StringBuilder();
        sb.append("Adding event to direct polling event list for realm: ");
        sb.append(realmName);
        sb.append(": ");
        sb.append(compuwareSecurityEvent);
	    logger.debug(sb.toString());
	}

	/**
	 * 
	 */
	public synchronized List<CompuwareSecurityEvent> getRecentCompuwareSecurityEvents(
	    long ageThresholdMillis, 
	    String realmName) {
	    
	    List<CompuwareSecurityEvent> recentServiceEventsList = getCompuwareSecurityEventList(realmName);
	    if (logger.isDebugEnabled()) {
	        logger.debug("Returning list of recent events for realm: " + realmName + ": " + recentServiceEventsList);
	    }
	    
        List<CompuwareSecurityEvent> list = new ArrayList<CompuwareSecurityEvent>();
        Iterator<CompuwareSecurityEvent> iterator = recentServiceEventsList.iterator();
        while (iterator.hasNext()) {
            CompuwareSecurityEvent compuwareSecurityEvent = iterator.next();
            long eventAge = compuwareSecurityEvent.getEventAge();
            if (eventAge > ageThresholdMillis) {
                list.add(compuwareSecurityEvent);        
            }
        }        
        
	    return list;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.event.IEventService#addCompuwareSecurityEventListener(com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventListener, java.lang.String)
	 */
    public synchronized void addCompuwareSecurityEventListener(
        ICompuwareSecurityEventListener compuwareSecurityEventListener,
        String realmName) {
        
        logger.debug("Adding event listener: [" + compuwareSecurityEventListener + "] for realm: [" + realmName + "].");
        Set<ICompuwareSecurityEventListener> compuwareSecurityEventListenerSet = getCompuwareSecurityEventListenerSet(realmName);
        compuwareSecurityEventListenerSet.add(compuwareSecurityEventListener);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.event.IEventService#getCompuwareSecurityEventListeners(java.lang.String)
     */
    public List<ICompuwareSecurityEventListener> getCompuwareSecurityEventListeners(String realmName) {
        
    	List<ICompuwareSecurityEventListener> list = new ArrayList<ICompuwareSecurityEventListener>();
    	Set<ICompuwareSecurityEventListener> compuwareSecurityEventListenerSet = getCompuwareSecurityEventListenerSet(realmName);
    	list.addAll(compuwareSecurityEventListenerSet);
        if (logger.isDebugEnabled()) {
            logger.debug("Returning event listener list:[" + list + "] for realm: [" + realmName + "].");    
        }    	
    	return list;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.event.IEventService#removeCompuwareSecurityEventListener(com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventListener, java.lang.String)
     */
    public synchronized void removeCompuwareSecurityEventListener(
        ICompuwareSecurityEventListener compuwareSecurityEventListener,
        String realmName) {
        
        logger.debug("Removing event listener: [" + compuwareSecurityEventListener + "] for realm: [" + realmName + "].");
        Set<ICompuwareSecurityEventListener> compuwareSecurityEventListenerSet = getCompuwareSecurityEventListenerSet(realmName);
        compuwareSecurityEventListenerSet.remove(compuwareSecurityEventListener);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.event.IEventService#removeAllCompuwareSecurityEventListeners(java.lang.String)
     */
    public synchronized void removeAllCompuwareSecurityEventListeners(String realmName) {
        
        Set<ICompuwareSecurityEventListener> compuwareSecurityEventListenerSet = getCompuwareSecurityEventListenerSet(realmName);
        compuwareSecurityEventListenerSet.clear();
        logger.debug("Removing all event listeners for realm: [" + realmName + "].");
    }

    /*
     * 
     * @param realmName
     * @return
     */
    private synchronized Set<ICompuwareSecurityEventListener> getCompuwareSecurityEventListenerSet(String realmName) {
        
        Set<ICompuwareSecurityEventListener> compuwareSecurityEventListenerSet = this.compuwareSecurityEventListeners.get(realmName);
        if (compuwareSecurityEventListenerSet == null) {
            
            logger.debug("Creating event listener set for realm: [" + realmName + "].");
            compuwareSecurityEventListenerSet = new HashSet<ICompuwareSecurityEventListener>();            
            this.compuwareSecurityEventListeners.put(realmName, compuwareSecurityEventListenerSet);
        }
        return compuwareSecurityEventListenerSet;
    }
    
    /*
     * 
     * @param realmName
     * @return
     */
    private synchronized List<CompuwareSecurityEvent> getCompuwareSecurityEventList(String realmName) {
        
        List<CompuwareSecurityEvent> compuwareSecurityEventList = COMPUWARE_SECURITY_EVENT_MAP.get(realmName);
        if (compuwareSecurityEventList == null) {
            
            logger.debug("Creating list to hold recent events for realm: [" + realmName + "].");
            compuwareSecurityEventList = new ArrayList<CompuwareSecurityEvent>();
            COMPUWARE_SECURITY_EVENT_MAP.put(realmName, compuwareSecurityEventList);
        }
        return compuwareSecurityEventList;
    }
}