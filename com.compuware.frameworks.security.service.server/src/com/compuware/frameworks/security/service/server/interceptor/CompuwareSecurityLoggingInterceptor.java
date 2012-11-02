/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2012 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.server.interceptor;

import java.util.ArrayList;
import java.util.List;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * 
 * @author tmyers
 */
public class CompuwareSecurityLoggingInterceptor implements MethodInterceptor {
    
    /*
     * (non-Javadoc)
     * @see org.aopalliance.intercept.MethodInterceptor#invoke(org.aopalliance.intercept.MethodInvocation)
     */
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {

        boolean logMethodInvocation = false;
        String methodName = methodInvocation.getMethod().getName();
        if (!methodName.startsWith("get") 
            && !methodName.startsWith("fireCompuwareSecurityEvent")
            && !methodName.startsWith("deauthenticate")) {
            
            logMethodInvocation = true;
        }
                        
        Object returnValue = null;
        try {
            
            try {
                
                returnValue = methodInvocation.proceed();
                
            } catch (Throwable t) {
                try {
                    Class<?> clazz = methodInvocation.getMethod().getDeclaringClass();
                    Logger logger = Logger.getLogger(clazz);
                    logger.error("Error occurred invoking method: " + methodName, t);
                } catch (Exception e) {
                    System.err.println("Logging interceptor could not log method exception: " + e.getMessage());
                }
                throw t;
            }
            
            return returnValue;
            
        } finally {
            if (logMethodInvocation) {
                try {
                    StringBuilder sb = new StringBuilder(512);
                    Class<?> clazz = methodInvocation.getMethod().getDeclaringClass();
                    Logger logger = Logger.getLogger(clazz);

                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    if (authentication != null) {
                        sb.append(authentication.getName());
                        sb.append(": ");
                    } else {
                        sb.append("UNAUTHENTICATED: ");
                    }
                    sb.append(methodName);
                    sb.append(" ");
                    
                    List<Object> argumentsList = new ArrayList<Object>();
                    Object[] argumentsArray = methodInvocation.getArguments();
                    if (argumentsArray != null && argumentsArray.length > 0) {
                        for (int i=0; i < argumentsArray.length; i++) {
                            argumentsList.add(argumentsArray[i]);
                        }
                    }
                    sb.append(argumentsList.toString());
                    
                    if (returnValue != null) {
                        sb.append(" - returnValue: ");
                        sb.append(returnValue);    
                    }
                    logger.info(sb.toString());
                    
                } catch (Exception e) {
                    System.err.println("Logging interceptor could not log method invocation: " + e.getMessage());
                }
            }
        }
    }
}