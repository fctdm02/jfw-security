/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product emails are trademarks of their respective owners.
 * 
 * Copyright 2010 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.model;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author tmyers
 * TODO: TDM: Need to either create a session interface or make some of these methods package private 
 */
@XmlRootElement
public final class CompuwareSecuritySession implements Authentication, Serializable {

   /** */
   private static final long serialVersionUID = 1L;
   
   /**
    *  
    */
   @XmlElement
   private String sessionId;
   
   /**
    *  
    */
   @XmlElement
   private long creationTimeMillis;
   
   /**
    *  
    */
   @XmlElement
   private long lastAccessTimeMillis;
   
   /**
    * 
    */
   @XmlElement
   private long accessCount;
   
   /**
    * Used to hold "host application" defined attributes 
    */
   private Map<String, Object> sessionAttributeMap;
   
   /* 
    * JAXB is the only intended caller of the private no-arg constructor. 
    * This flag is used to allow JAXB to invoke the setAuthenticated method
    * when reconstructing a security token returned from a web service call.
    */  
   private boolean jaxbCaller = false;
   
   /*
    * This constructor is for JAXB support.
    */
   @SuppressWarnings("unused")
   private CompuwareSecuritySession() {       
       this.jaxbCaller = true;
   }   
   
   /**
    *  
    */
   @XmlElement
   private CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken;

   /**
    * 
    * @param sessionId
    * @param compuwareSecurityAuthenticationToken
    */
   public CompuwareSecuritySession(
       String sessionId,
       CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken) {
       
       this.sessionId = sessionId;
       this.compuwareSecurityAuthenticationToken = compuwareSecurityAuthenticationToken;
       
       this.creationTimeMillis = System.currentTimeMillis();
       this.lastAccessTimeMillis = this.creationTimeMillis;
       this.accessCount = 0;
       
       this.sessionAttributeMap = new HashMap<String, Object>();
   }
   
   /**
    * 
    * @param key
    * @param value
    */
   public void setSessionAtttribute(String key, Object value) {
       this.sessionAttributeMap.put(key, value);
   }
   
   /**
    * 
    * @param key
    * @return
    */
   public Object getSessionAttribute(String key) {
       return this.sessionAttributeMap.get(key);
   }
   
   /**
    * 
    * @param key
    * @return
    */
   public Object removeSessionAttribute(String key) {
       return this.sessionAttributeMap.remove(key);
   }
   
   /**
    * @return the sessionId
    */
   public String getSessionId() {
       return this.sessionId;
   }

   /**
    * @return the creationTimeMillis
    */
   public long getCreationTimeMillis() {
       return this.creationTimeMillis;
   }

   /**
    * @return the lastAccessTimeMillis
    */
   public long getLastAccessTimeMillis() {
       return this.lastAccessTimeMillis;
   }

   /**
    * @return the accessCount
    */
   public long getAccessCount() {
       return this.accessCount;
   }

   /**
    * Increments the <code>accessCount</code>
    */
   public void incrementAccessCount() {
       this.accessCount = this.accessCount + 1L;
       this.lastAccessTimeMillis = System.currentTimeMillis();
   }
   
   /**
    * @return the compuwareSecurityAuthenticationToken
    */
   public CompuwareSecurityAuthenticationToken getCompuwareSecurityAuthenticationToken() {
       return this.compuwareSecurityAuthenticationToken;
   }
 
   /*
    * (non-Javadoc)
    * @see org.springframework.security.core.Authentication#getAuthorities()
    */
   public Collection<GrantedAuthority> getAuthorities() {
       return this.compuwareSecurityAuthenticationToken.getAuthorities();
   }
   
   /*
    * (non-Javadoc)
    * @see org.springframework.security.core.Authentication#getCredentials()
    */
   public Object getCredentials() {
       return this.compuwareSecurityAuthenticationToken.getCredentials();
   }
   
   /*
    * (non-Javadoc)
    * @see org.springframework.security.core.Authentication#getDetails()
    */
   public Object getDetails() {
       return this.compuwareSecurityAuthenticationToken.getDetails();
   }
   
   /*
    * (non-Javadoc)
    * @see org.springframework.security.core.Authentication#getPrincipal()
    */
   public Object getPrincipal() {
       return this.compuwareSecurityAuthenticationToken.getPrincipal();
   }
   
   /*
    * (non-Javadoc)
    * @see org.springframework.security.core.Authentication#isAuthenticated()
    */
   public boolean isAuthenticated() {
       return this.compuwareSecurityAuthenticationToken.isAuthenticated();
   }
   
   /*
    * (non-Javadoc)
    * @see org.springframework.security.core.Authentication#setAuthenticated(boolean)
    */
   public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
       if (!this.jaxbCaller) {
           throw new IllegalArgumentException("setAuthenticated(" + isAuthenticated + ") cannot be called from CompuwareSecuritySession.");
       }
   }
 
   /*
    * (non-Javadoc)
    * @see java.security.Principal#getName()
    */
   public String getName() {
       return this.compuwareSecurityAuthenticationToken.getName();
   }
   
   /*
    * (non-Javadoc)
    * @see java.lang.Object#equals(java.lang.Object)
    */
   public boolean equals(Object another) {
       return this.compuwareSecurityAuthenticationToken.equals(another);
   }
   
   /*
    * (non-Javadoc)
    * @see java.lang.Object#hashCode()
    */
   public int hashCode() {
       return this.compuwareSecurityAuthenticationToken.hashCode();    
   }
      
   /*
    * (non-Javadoc)
    * @see java.lang.Object#toString()
    */
   public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append("{CompuwareSecurityEvent: ");
      sb.append(", sessionId: ");
      sb.append(this.sessionId);
      sb.append(", creationTimeMillis: ");
      sb.append(this.creationTimeMillis);            
      sb.append(", lastAccessTimeMillis: ");
      sb.append(this.lastAccessTimeMillis);            
      sb.append(", accessCount: ");
      sb.append(this.accessCount);            
      sb.append(", sessionAttributeMap: ");
      sb.append(this.sessionAttributeMap);            
      sb.append(", authentication: ");
      sb.append(this.compuwareSecurityAuthenticationToken);            
      sb.append("}");
      return sb.toString();
   }
}