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

import java.util.List;

import org.springframework.security.access.annotation.Secured;

import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySession;
import com.compuware.frameworks.security.service.api.model.exception.MaxSessionsPerUserExceededException;
import com.compuware.frameworks.security.service.api.model.exception.SessionNotFoundException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public interface ISessionService {
    
    /**
     * If this is called after initialization, any existing sessions are invalidated.
     *  
     * @param sessionMonitorIntervalMillis How often sessions are validated.  
     * Permissible values are between 1000 (1 sec.) and 600000 (10 min.)  
     * @param maxInactiveSessionTimeoutMinutes How often a session can be inactive before 
     * being invalidated.
     * @param maxSessionLifeMinutes How long a session can be alive with constant activity 
     * before being invalidated.
     * @param maxSessionsPerUser If -1, then the user can have an unlimited number of 
     * concurrent sessions
     * 
     * @throws ValidationException
     */
    @Secured({IManagementService.JFW_SEC_CONFIG_ROLENAME})
    void configureSessionServiceHelper(
        long sessionMonitorIntervalMillis,
        int maxInactiveSessionTimeoutMinutes,
        int maxSessionLifeMinutes,
        int maxSessionsPerUser) throws ValidationException;
    
    /**
     * Defines how many distinct sessions a user can have. 
     * For example, a user may log in from different workstations
     * or instantiate multiple sessions using different browsers or
     * browser instances.
     * 
     * @param maxSessionsPerUser
     * 
     * @throws ValidationException
     */
    void setMaxSessionsPerUser(int maxSessionsPerUser) throws ValidationException;
    
    /**
     * Defines how long a user's session remains valid after the
     * last access time.  Once this timeout period has been met,
     * the session will be invalidated.
     * 
     * @param maxInactiveSessionTimeoutMinutes
     * 
     * @throws ValidationException
     */
    void setMaxInactiveSessionTimeoutMinutes(int maxInactiveSessionTimeoutMinutes) throws ValidationException;
    
    /**
     * Defines how long a user's session remains valid given constant
     * access.  In other words, how long a session remains invalid if
     * it doesn't time out.
     *  
     * @param maxSessionLifeMinutes
     * 
     * @throws ValidationException
     */
    void setMaxSessionLifeMinutes(int maxSessionLifeMinutes) throws ValidationException;
    
    /**
     * Defines how often the session manager performs a check of all existing 
     * sessions and does the following for each session whose inactive time
     * exceeds the session timeout period:
     * <ol>
     *   <li> Removes the session from the session store</li>
     *   <li> Sends a <code>CompuwareSecuritySessionExpiredEvent</code> to all registered listeners. </li>
     * </ol>
     * 
     * @param sessionMonitorIntervalMillis
     * 
     * @throws ValidationException
     */
    void setSessionMonitorIntervalMillis(long sessionMonitorIntervalMillis) throws ValidationException;

    /**
     * Upon creation of a session, a <code>CompuwareSecuritySessionCreatedEvent</code> 
     * is sent to all registered listeners.
     * 
     * @param compuwareSecurityAuthenticationToken
     * 
     * @return the <code>sessionId</code>, which is a randomly generated number.
     * 
     * @throws MaxSessionsPerUserExceededException
     */
    String createSession(CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken)
    throws MaxSessionsPerUserExceededException;

    /**
     * Upon creation of a session, a <code>CompuwareSecuritySessionCreatedEvent</code> 
     * is sent to all registered listeners.
     * 
     * @param compuwareSecurityAuthenticationToken
     * 
     * @return the <code>CompuwareSecuritySession</code>, that was just created.
     * 
     * @throws MaxSessionsPerUserExceededException
     */
    CompuwareSecuritySession createAndReturnSession(CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken)
    throws MaxSessionsPerUserExceededException;
    
    /**
     * Retrieves the session identified by <code>sessionId</code>.  In addition,
     * the <code>lastAccessTime</code> and <code>accessCount</code> are updated
     * and a <code>CompuwareSecuritySessionAccessedEvent</code> is sent to all  
     * registered listeners.
     * 
     * @param sessionId
     * @return
     * @throws SessionNotFoundException
     */
    CompuwareSecuritySession getSession(String sessionId) 
    throws SessionNotFoundException;
    
    /**
     * 
     * @return
     */
    List<CompuwareSecuritySession> getAllSessions();
    
    /**
     * @return <code>true</code> if the session identified by 
     * <code>sessionId</code> is valid, <code>false</code> otherwise.
     * 
     * @throws SessionNotFoundException
     */
    boolean isSessionValid(String sessionId)
    throws SessionNotFoundException;;
    
    /**
     * Removes the session identified by <code>sessionId</code> from
     * the session store.
     * <p>
     * In addition, a <code>CompuwareSecuritySessionInvalidatedEvent</code> 
     * is sent to all registered listeners.
     * 
     * @param sessionId
     * 
     * @throws SessionNotFoundException
     */
    void invalidateSession(String sessionId) 
    throws SessionNotFoundException;
    
    /**
     * Removes all sessions from the session store.
     * <p>
     * In addition, for each session, a <code>CompuwareSecuritySessionInvalidatedEvent</code> 
     * is sent to all registered listeners.
     */
    void invalidateAllSessions();
    
    /**
     * Performs an explicit check of all sessions with respect to validity of session
     * life and session timeout.  For each session that is invalidated, a 
     * <code>CompuwareSecuritySessionInvalidatedEvent</code> 
     * is sent to all registered listeners.
     * <p>
     * NOTE: This is the same operation that is to be performed implicitly every 
     * <code>sessionMonitorIntervalMillis</code> milliseconds.
     */
    void validateAllSessions();
    
    /**
     * Returns the number of valid sessions currently being stored in the session store.
     * 
     * @return
     */
    int getSessionCount();
}