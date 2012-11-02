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
package com.compuware.frameworks.security.service.api.session;

/**
 * 
 * Used to validate sessions every <code>sessionMonitorIntervalMillis</code>
 * milliseconds.
 * 
 */
public final class SessionMonitor implements Runnable {

    /* */
    private long sessionMonitorIntervalMillis = 5000;

    /* */
    private SessionServiceHelper sessionServiceHelper;

    /**
     * 
     * @param sessionServiceHelper
     * @param sessionMonitorIntervalMillis
     */
    SessionMonitor(SessionServiceHelper sessionServiceHelper, long sessionMonitorIntervalMillis) {
        this.sessionMonitorIntervalMillis = sessionMonitorIntervalMillis;
        this.sessionServiceHelper = sessionServiceHelper;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Runnable#run()
     */
    public void run() {

        do {
            
            sessionServiceHelper.validateAllSessions();

            synchronized (this) {
                try {
                    wait(this.sessionMonitorIntervalMillis);
                } catch (InterruptedException e) {
                }
            }
        } while (true);
    }
}