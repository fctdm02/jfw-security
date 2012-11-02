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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.log4j.Logger;

import com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventListener;
import com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventProducer;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySession;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySessionAccessedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySessionCreatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySessionInvalidatedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityUserDeletedEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityUserEvent;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityUserUpdatedEvent;
import com.compuware.frameworks.security.service.api.model.exception.MaxSessionsPerUserExceededException;
import com.compuware.frameworks.security.service.api.model.exception.SessionNotFoundException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
public class SessionServiceHelper implements ICompuwareSecurityEventListener, ICompuwareSecurityEventProducer {

    /* */
    private final Logger logger = Logger.getLogger(SessionServiceHelper.class);
    
    /* */
    private static final int NUM_MILLIS_IN_MINUTE = 60000;

    /* */
    private int maxSessionsPerUser;
    
    /* */
    private long sessionMonitorIntervalMillis;
    
    /* */
    private int maxInactiveSessionTimeoutMinutes;
    
    /* */
    private int maxSessionLifeMinutes;
    
    /* */
    private SessionMonitor sessionMonitor;
    
    /* */
    private Map<String, CompuwareSecuritySession> sessionMap;
    
    /* */
    private ICompuwareSecurityEventProducer eventProducer;

    /**
     * 
     * @param sessionMonitorIntervalMillis How often sessions are validated.  
     * Permissible values are between 1000 (1 sec.) and 600000 (10 min.)  
     * @param maxInactiveSessionTimeoutMinutes How often a session can be inactive before being invalidated.
     * @param maxSessionLifeMinutes How long a session can be alive with constant activity before being invalidated.
     * @param maxSessionsPerUser If -1, then the user can have an unlimited number of concurrent sessions
     * @param eventProducer The ICompuwareSecurityEventProducer to use when sessions are invalidated.
     * @throws ValidationException
     */
    public SessionServiceHelper(
        long sessionMonitorIntervalMillis,
        int maxInactiveSessionTimeoutMinutes,
        int maxSessionLifeMinutes,
        int maxSessionsPerUser,
        ICompuwareSecurityEventProducer eventProducer) throws ValidationException {
        
        setSessionMonitorIntervalMillis(sessionMonitorIntervalMillis);
        setMaxInactiveSessionTimeoutMinutes(maxInactiveSessionTimeoutMinutes);
        setMaxSessionLifeMinutes(maxSessionLifeMinutes);
        setMaxSessionsPerUser(maxSessionsPerUser);
                        
        this.eventProducer = eventProducer;    
        
        this.sessionMap = new HashMap<String, CompuwareSecuritySession>();

        this.sessionMonitor = new SessionMonitor(this, this.sessionMonitorIntervalMillis);
        Thread t = new Thread(this.sessionMonitor);
        t.setDaemon(true);
        t.setName("CSSSessionMonitor");
        t.start();
        
        StringBuilder sb = new StringBuilder(512);
        sb.append("Initializing ");
        sb.append(this);
        logger.debug(sb.toString());
    }
            
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#setMaxSessionsPerUser(int)
     */
    public final void setMaxSessionsPerUser(int maxSessionsPerUser) throws ValidationException {
        
        if (maxSessionsPerUser != -1 && (maxSessionsPerUser < -1 || maxSessionsPerUser == 0)) {
            throw new ValidationException(ValidationException.FIELD_MAX_SESSIONS_PER_USER, ValidationException.REASON_MUST_BE_A_INTEGRAL_NUMBER);
        }
        
        logger.debug("Setting maxSessionsPerUser: " + maxSessionsPerUser);
        this.maxSessionsPerUser = maxSessionsPerUser;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#setMaxInactiveSessionTimeoutMinutes(int)
     */
    public final void setMaxInactiveSessionTimeoutMinutes(int maxInactiveSessionTimeoutMinutes) throws ValidationException {
        
        if (maxInactiveSessionTimeoutMinutes < IManagementService.MIN_INACTIVE_SESSION_TIMEOUT_MINUTES 
            || maxInactiveSessionTimeoutMinutes > IManagementService.MAX_INACTIVE_SESSION_TIMEOUT_MINUTES) {
            String reason = ValidationException.REASON_MUST_BE_BETWEEN;
            reason = reason.replace(ValidationException.TOKEN_ZERO, Long.toString(IManagementService.MIN_SESSION_MONITOR_INTERVAL_MILLIS));
            reason = reason.replace(ValidationException.TOKEN_ONE, Long.toString(IManagementService.MAX_SESSION_MONITOR_INTERVAL_MILLIS));
            throw new ValidationException(ValidationException.FIELD_MAX_INACTIVE_SESSION_TIMEOUT_MINUTES, reason);
        }
                            
        logger.debug("Setting maxInactiveSessionTimeoutMinutes: " + maxInactiveSessionTimeoutMinutes);
        this.maxInactiveSessionTimeoutMinutes = maxInactiveSessionTimeoutMinutes;
        
        // The following is to allow the unit tests to test session life behavior without taking an inordinate amount of time.
        String strMaxInactiveSessionTimeoutMinutes = System.getProperty("maxInactiveSessionTimeoutMinutes");
        if (strMaxInactiveSessionTimeoutMinutes != null) {
            logger.debug("TEST OVERRIDE: Setting maxInactiveSessionTimeoutMinutes to 0.");
            this.maxInactiveSessionTimeoutMinutes = 0;
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#setMaxSessionLifeMinutes(int)
     */
    public final void setMaxSessionLifeMinutes(int maxSessionLifeMinutes) throws ValidationException {
        
        if (maxSessionLifeMinutes < IManagementService.MIN_SESSION_LIFE_MINUTES 
            || maxSessionLifeMinutes > IManagementService.MAX_SESSION_LIFE_MINUTES) {
            
            String reason = ValidationException.REASON_MUST_BE_BETWEEN;
            reason = reason.replace(ValidationException.TOKEN_ZERO, Long.toString(IManagementService.MIN_SESSION_LIFE_MINUTES));
            reason = reason.replace(ValidationException.TOKEN_ONE, Long.toString(IManagementService.MAX_SESSION_LIFE_MINUTES));
            throw new ValidationException(ValidationException.FIELD_MAX_SESSION_LIFE_MINUTES, reason);
        }
                        
        logger.debug("Setting maxSessionLifeMinutes: " + maxSessionLifeMinutes);
        this.maxSessionLifeMinutes = maxSessionLifeMinutes;
        
        // The following is to allow the unit tests to test session life behavior without taking an inordinate amount of time.
        String strMaxSessionLifeMinutesOverride = System.getProperty("maxSessionLifeMinutes");
        if (strMaxSessionLifeMinutesOverride != null) {
            logger.debug("TEST OVERRIDE: Setting maxSessionLifeMinutes to 0.");
            this.maxSessionLifeMinutes = 0;
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#setSessionMonitorIntervalMillis(long)
     */
    public final void setSessionMonitorIntervalMillis(long sessionMonitorIntervalMillis) throws ValidationException {
        
        if (sessionMonitorIntervalMillis < IManagementService.MIN_SESSION_MONITOR_INTERVAL_MILLIS 
            || sessionMonitorIntervalMillis > IManagementService.MAX_SESSION_MONITOR_INTERVAL_MILLIS) {
            
            String reason = ValidationException.REASON_MUST_BE_BETWEEN;
            reason = reason.replace(ValidationException.TOKEN_ZERO, Long.toString(IManagementService.MIN_SESSION_MONITOR_INTERVAL_MILLIS));
            reason = reason.replace(ValidationException.TOKEN_ONE, Long.toString(IManagementService.MAX_SESSION_MONITOR_INTERVAL_MILLIS));
            throw new ValidationException(ValidationException.FIELD_SESSION_MONITOR_INTERVAL_MILLIS, reason);
        }
        
        logger.debug("Setting sessionMonitorIntervalMillis: " + sessionMonitorIntervalMillis);
        this.sessionMonitorIntervalMillis = sessionMonitorIntervalMillis;
    }

    /**
     * 
     * @param compuwareSecurityAuthenticationToken
     * @return
     * @throws MaxSessionsPerUserExceededException
     */
    public final CompuwareSecuritySession createSession(CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken)
    throws MaxSessionsPerUserExceededException {

        int sessionCount = 0;
        String username = compuwareSecurityAuthenticationToken.getUsername();
        
        Iterator<String> iterator = this.sessionMap.keySet().iterator();
        while (iterator.hasNext()) {
            
            String sessionId = iterator.next();
            CompuwareSecuritySession session = this.sessionMap.get(sessionId);
            if (session.getCompuwareSecurityAuthenticationToken().getUsername().equals(username)) {
                sessionCount = sessionCount + 1;
            }
        }
        if (this.maxSessionsPerUser > 0 && sessionCount >= this.maxSessionsPerUser) {
            throw new MaxSessionsPerUserExceededException("User: " + username + " exceeded max. session count: " + this.maxSessionsPerUser);
        }
                
        UUID uuid = UUID.randomUUID();
        String sessionId = uuid.toString();
        CompuwareSecuritySession session = new CompuwareSecuritySession(sessionId, compuwareSecurityAuthenticationToken);
        this.sessionMap.put(sessionId, session);
                        
        // Fire an event so that listeners can be notified of this session being created.
        CompuwareSecuritySessionCreatedEvent compuwareSecuritySessionCreatedEvent = new CompuwareSecuritySessionCreatedEvent(
            compuwareSecurityAuthenticationToken.getUsername(),    
            sessionId,
            session.getCompuwareSecurityAuthenticationToken().getRealmName());
        
        fireCompuwareSecurityEvent(compuwareSecuritySessionCreatedEvent);
        
        StringBuilder sb = new StringBuilder(512);
        sb.append("Creating session: [");
        sb.append(sessionId);
        sb.append("], for user: ["); 
        sb.append(username);
        sb.append("], sessionCount: [");
        sb.append(sessionCount);
        logger.debug(sb.toString());
        
        return session;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.client.api.ISessionServiceClient#getSession(java.lang.String)
     */
    public final CompuwareSecuritySession getSession(String sessionId) 
    throws SessionNotFoundException {
                
        CompuwareSecuritySession session = null;
        synchronized (this.sessionMap) {
            session = this.sessionMap.get(sessionId);    
        }
        if (session == null) {
            throw new SessionNotFoundException("No valid session found with sessionId: [" + sessionId + "].");
        }
        session.incrementAccessCount();
        
        // Fire an event so that listeners can be notified of this session being accessed.
        CompuwareSecuritySessionAccessedEvent compuwareSecuritySessionAccessedEvent = new CompuwareSecuritySessionAccessedEvent(
            sessionId,
            session.getCompuwareSecurityAuthenticationToken().getRealmName());
        
        fireCompuwareSecurityEvent(compuwareSecuritySessionAccessedEvent);
        
        return session;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#getAllSessions()
     */
    public final List<CompuwareSecuritySession> getAllSessions() {
        
        List<CompuwareSecuritySession> list = new ArrayList<CompuwareSecuritySession>();
        synchronized (this.sessionMap) {
            Iterator<String> iterator = this.sessionMap.keySet().iterator();
            while (iterator.hasNext()) {
                
                String sessionId = iterator.next();
                CompuwareSecuritySession session = this.sessionMap.get(sessionId);
                list.add(session);
            }
        }
        return list;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#isSessionValid(java.lang.String)
     */
    public final boolean isSessionValid(String sessionId) 
    throws SessionNotFoundException {
        CompuwareSecuritySession session = this.getSession(sessionId);
        return this.isSessionValid(session);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.client.api.ISessionServiceClient#invalidateSession(java.lang.String)
     */
    public final void invalidateSession(String sessionId) 
    throws SessionNotFoundException {
        
        CompuwareSecuritySession session = null;
        synchronized (this.sessionMap) {
            session = this.sessionMap.get(sessionId);
        }
        if (session != null) {
            invalidateSession(session);    
        }
    }

    /*
     * 
     * @param session
     */
    private void invalidateSession(CompuwareSecuritySession session) {

        String sessionId = session.getSessionId();
        StringBuilder sb = new StringBuilder(512);
        sb.append("Invalidating session: [");
        sb.append(sessionId);
        logger.debug(sb.toString());
        
        synchronized (this.sessionMap) {
            this.sessionMap.remove(sessionId);    
        }
                        
        // Fire an event so that listeners can be notified of this session being invalidated.
        CompuwareSecuritySessionInvalidatedEvent compuwareSecuritySessionInvalidatedEvent = new CompuwareSecuritySessionInvalidatedEvent(
            sessionId,
            session.getCompuwareSecurityAuthenticationToken().getRealmName());
        
        fireCompuwareSecurityEvent(compuwareSecuritySessionInvalidatedEvent);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#invalidateAllSessions()
     */
    public final void invalidateAllSessions() {
        
        logger.debug("Invalidating all sessions");
        List<CompuwareSecuritySession> sessionList = new ArrayList<CompuwareSecuritySession>();
        synchronized (this.sessionMap) {
            Iterator<String> iterator = this.sessionMap.keySet().iterator();
            while (iterator.hasNext()) {
                String sessionId = iterator.next();
                CompuwareSecuritySession session = this.sessionMap.get(sessionId);
                sessionList.add(session);
            }
        }
        int size = sessionList.size();
        for (int i=0; i < size; i++) {
            CompuwareSecuritySession session = sessionList.get(i);
            invalidateSession(session);
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.client.api.ISessionServiceClient#validateAllSessions()
     */
    public final void validateAllSessions() {
        
        List<CompuwareSecuritySession> invalidSessionList = new ArrayList<CompuwareSecuritySession>();
        
        synchronized(this.sessionMap) {
            
            List<String> sessionIdList = new ArrayList<String>();
            sessionIdList.addAll(this.sessionMap.keySet());
            for (int i=0; i < sessionIdList.size(); i++) {
                
                String sessionId = sessionIdList.get(i);
                CompuwareSecuritySession session = this.sessionMap.get(sessionId);
                
                boolean isSessionValid = this.isSessionValid(session);
                if (!isSessionValid) {
                    invalidSessionList.add(session);
                }
            }
        }
                
        for (int i=0; i < invalidSessionList.size(); i++) {
            
            invalidateSession(invalidSessionList.get(i));
        }        
    }

    /*
     * 
     * @param session
     * @return
     */
    private boolean isSessionValid(CompuwareSecuritySession session) {

        long currentTimeMillis = System.currentTimeMillis();
        long lastAccessTimeMillis = session.getLastAccessTimeMillis();        
        long lastAccessTimeDelta = currentTimeMillis - lastAccessTimeMillis;
        long sessionTimeoutMillisThreshold = this.maxInactiveSessionTimeoutMinutes * NUM_MILLIS_IN_MINUTE;         
        if (lastAccessTimeDelta >= sessionTimeoutMillisThreshold) {
            return false;
        }
        
        long creationTimeMillis = session.getCreationTimeMillis();
        long creationTimeDelta = currentTimeMillis - creationTimeMillis;
        long sessionLifeMillisThreshold = this.maxSessionLifeMinutes * NUM_MILLIS_IN_MINUTE;
        if (creationTimeDelta >= sessionLifeMillisThreshold) {
            return false;
        }
        
        return true;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#getSessionCount()
     */
    public final int getSessionCount() {
        synchronized (this.sessionMap) {
            return this.sessionMap.size();
        }
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventListener#compuwareSecurityEventOccurred(com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent)
     */
    public final void compuwareSecurityEventOccurred(CompuwareSecurityEvent compuwareSecurityEvent) {
        
        // We want to respond to events where users are updated/deleted by invalidating 
        // any session that they may have.
        if (compuwareSecurityEvent instanceof CompuwareSecurityUserDeletedEvent 
            || compuwareSecurityEvent instanceof CompuwareSecurityUserUpdatedEvent) {
            
            String subjectUsername = ((CompuwareSecurityUserEvent)compuwareSecurityEvent).getSubjectUsername();
            
            List<CompuwareSecuritySession> sessionList = this.getSessionsForUser(subjectUsername);
            Iterator<CompuwareSecuritySession> iterator = sessionList.iterator();
            while (iterator.hasNext()) {
                
                CompuwareSecuritySession session = iterator.next();
                invalidateSession(session);            
            }
        }
    }
    
    /*
     * 
     * @param username
     * @return
     */
    private List<CompuwareSecuritySession> getSessionsForUser(String username) {
        
        List<CompuwareSecuritySession> sessionList = new ArrayList<CompuwareSecuritySession>();
 
        synchronized (this.sessionMap) {
            Iterator<String> iterator = this.sessionMap.keySet().iterator();
            while (iterator.hasNext()) {
                
                String sessionId = iterator.next();
                CompuwareSecuritySession session = this.sessionMap.get(sessionId);
                if (session.getCompuwareSecurityAuthenticationToken().getUsername().equals(username)) {
                    sessionList.add(session);
                }
            }        
        }
        
        return sessionList;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.event.ICompuwareSecurityEventProducer#fireCompuwareSecurityEvent(com.compuware.frameworks.security.service.api.model.CompuwareSecurityEvent)
     */
    public void fireCompuwareSecurityEvent(CompuwareSecurityEvent compuwareSecurityEvent) {
        this.eventProducer.fireCompuwareSecurityEvent(compuwareSecurityEvent);
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(this.getClass().getSimpleName());
        sb.append(", maxSessionsPerUser: ");
        sb.append(this.maxSessionsPerUser);
        sb.append(", sessionMonitorIntervalMillis: ");
        sb.append(this.sessionMonitorIntervalMillis);
        sb.append(", maxInactiveSessionTimeoutMinutes: ");
        sb.append(this.maxInactiveSessionTimeoutMinutes);
        sb.append(", maxSessionLifeMinutes: ");
        sb.append(this.maxSessionLifeMinutes);
        sb.append(", sessionMap: ");
        sb.append(this.sessionMap);
        sb.append("}");
        return sb.toString();
    }
}