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
package com.compuware.frameworks.security.service.server.session;

import java.util.List;

import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.service.api.audit.IAuditService;
import com.compuware.frameworks.security.service.api.event.IEventService;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySession;
import com.compuware.frameworks.security.service.api.model.exception.MaxSessionsPerUserExceededException;
import com.compuware.frameworks.security.service.api.model.exception.SessionNotFoundException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;
import com.compuware.frameworks.security.service.api.session.ISessionService;
import com.compuware.frameworks.security.service.api.session.SessionServiceHelper;
import com.compuware.frameworks.security.service.server.AbstractService;

/**
 * 
 * @author tmyers
 * 
 */
public final class SessionServiceImpl extends AbstractService implements ISessionService {

    /* */
    private SessionServiceHelper sessionServiceHelper;
    
    /**
     * @param eventService
     * @param auditService
     * @param multiTenancyRealmDao
     * @throws ValidationException
     */
    public SessionServiceImpl(
            IEventService eventService,
            IAuditService auditService,
            IMultiTenancyRealmDao multiTenancyRealmDao) throws ValidationException {
        super(auditService, eventService, multiTenancyRealmDao);

        // TODO: TDM: We want to use a different session manager per realm
        // TODO: TDM: Eventually, the session config needs to deal with the realm.
        
        long sessionMonitorIntervalMillis = IManagementService.DEFAULT_REALM_SESSION_MONITOR_INTERVAL_MILLIS;
        int maxInactiveSessionTimeoutMinutes = IManagementService.DEFAULT_REALM_SESSION_TIMEOUT_IN_MINUTES;
        int maxSessionLifeMinutes = IManagementService.DEFAULT_REALM_SESSION_MAX_LENGTH_IN_MINUTES;
        int maxSessionsPerUser = IManagementService.DEFAULT_REALM_SESSION_MAX_CONCURRENT_LOGINS;
        
        this.configureSessionServiceHelper(
            eventService,
            sessionMonitorIntervalMillis, 
            maxInactiveSessionTimeoutMinutes, 
            maxSessionLifeMinutes,
            maxSessionsPerUser);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#configureSessionServiceHelper(long, int, int, int)
     */
    public void configureSessionServiceHelper(
        long sessionMonitorIntervalMillis,
        int maxInactiveSessionTimeoutMinutes,
        int maxSessionLifeMinutes,
        int maxSessionsPerUser) throws ValidationException {
        
        configureSessionServiceHelper(
            getEventService(), 
            sessionMonitorIntervalMillis, 
            maxInactiveSessionTimeoutMinutes, 
            maxSessionLifeMinutes, 
            maxSessionsPerUser);
    }

    /**
     * 
     * @param eventService
     * @param sessionMonitorIntervalMillis
     * @param maxInactiveSessionTimeoutMinutes
     * @param maxSessionLifeMinutes
     * @param maxSessionsPerUser
     * @throws ValidationException
     */
    private void configureSessionServiceHelper(
        IEventService eventService,    
        long sessionMonitorIntervalMillis,
        int maxInactiveSessionTimeoutMinutes,
        int maxSessionLifeMinutes,
        int maxSessionsPerUser) throws ValidationException {
        
        // If we are setting a new session service helper, then remove the old one as a listener.
        if (this.sessionServiceHelper != null) {
            eventService.removeCompuwareSecurityEventListener(
                this.sessionServiceHelper, 
                IManagementService.DEFAULT_REALM_NAME);
            this.sessionServiceHelper.invalidateAllSessions();
        }

        // Create a new session service helper with the given session mgmt. settings.
        this.sessionServiceHelper = new SessionServiceHelper(
            sessionMonitorIntervalMillis,
            maxInactiveSessionTimeoutMinutes,
            maxSessionLifeMinutes,
            maxSessionsPerUser,
            this);
        
        // We want to listen for events for all realms
        eventService.addCompuwareSecurityEventListener(
            this.sessionServiceHelper, 
            IManagementService.DEFAULT_REALM_NAME);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#setMaxSessionsPerUser(int)
     */
    public void setMaxSessionsPerUser(int maxSessionsPerUser) throws ValidationException {
        this.sessionServiceHelper.setMaxSessionsPerUser(maxSessionsPerUser);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#setMaxInactiveSessionTimeoutMinutes(int)
     */
    public void setMaxInactiveSessionTimeoutMinutes(int maxInactiveSessionTimeoutMinutes) throws ValidationException {
        this.sessionServiceHelper.setMaxInactiveSessionTimeoutMinutes(maxInactiveSessionTimeoutMinutes);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#setMaxSessionLifeMinutes(int)
     */
    public void setMaxSessionLifeMinutes(int maxSessionLifeMinutes) throws ValidationException {
        this.sessionServiceHelper.setMaxSessionLifeMinutes(maxSessionLifeMinutes);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#setSessionMonitorIntervalMillis(int)
     */
    public void setSessionMonitorIntervalMillis(long sessionMonitorIntervalMillis) throws ValidationException {
        this.sessionServiceHelper.setSessionMonitorIntervalMillis(sessionMonitorIntervalMillis);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#createSession(com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken)
     */
    public String createSession(CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken)
    throws MaxSessionsPerUserExceededException {
        CompuwareSecuritySession compuwareSecuritySession = this.sessionServiceHelper.createSession(compuwareSecurityAuthenticationToken);
        return compuwareSecuritySession.getSessionId();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#createAndReturnSession(com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken)
     */
    public CompuwareSecuritySession createAndReturnSession(CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken)
    throws MaxSessionsPerUserExceededException {
        return this.sessionServiceHelper.createSession(compuwareSecurityAuthenticationToken);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#getSession(java.lang.String)
     */
    public CompuwareSecuritySession getSession(String sessionId) 
    throws SessionNotFoundException {
        return this.sessionServiceHelper.getSession(sessionId);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#getAllSessions()
     */
    public List<CompuwareSecuritySession> getAllSessions() {
        return this.sessionServiceHelper.getAllSessions();
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#isSessionValid(java.lang.String)
     */
    public boolean isSessionValid(String sessionId) 
    throws SessionNotFoundException {
        return this.sessionServiceHelper.isSessionValid(sessionId);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.client.api.ISessionServiceClient#invalidateSession(java.lang.String)
     */
    public void invalidateSession(String sessionId) 
    throws SessionNotFoundException {
        this.sessionServiceHelper.invalidateSession(sessionId);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#invalidateAllSessions()
     */
    public void invalidateAllSessions() {
        this.sessionServiceHelper.invalidateAllSessions();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#validateAllSessions()
     */
    public void validateAllSessions() {
        this.sessionServiceHelper.validateAllSessions();
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.service.api.session.ISessionService#getSessionCount()
     */
    public int getSessionCount() {
        return this.sessionServiceHelper.getSessionCount();
    }
}