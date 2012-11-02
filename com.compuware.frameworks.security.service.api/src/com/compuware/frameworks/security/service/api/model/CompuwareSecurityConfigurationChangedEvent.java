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
package com.compuware.frameworks.security.service.api.model;

import java.util.Iterator;
import java.util.Map;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author tmyers
 *
 */
@XmlRootElement
public final class CompuwareSecurityConfigurationChangedEvent extends CompuwareSecurityConfigurationEvent {

    /* */
    private static final long serialVersionUID = 1L;

    /* */
    private String oldConfiguration;
    
    /* */
    private String newConfiguration;
    
    /**
     * 
     */
    protected CompuwareSecurityConfigurationChangedEvent() {
        super();
    }
    
    /**
     * 
     * @param oldConfiguration
     * @param newConfiguration
     * @param initiatingUsername
     * @param originatingIpAddress
     * @param originatingHostname
     * @param realmName
     */
    public CompuwareSecurityConfigurationChangedEvent(
        Map<String, String> oldLdapConfiguration,
        Map<String, String> newLdapConfiguration,
        String initiatingUsername,
        String originatingIpAddress,
        String originatingHostname,
        String realmName) {
        
        super(
            initiatingUsername,
            originatingIpAddress,
            originatingHostname,
            "User: [" + initiatingUsername + "] changed configuration on: [" + new java.util.Date(System.currentTimeMillis()) + "].",
            realmName);
        this.oldConfiguration = cleanConfigurationForDisplay(oldLdapConfiguration);
        this.newConfiguration = cleanConfigurationForDisplay(newLdapConfiguration);
    }
    
    /**
     * @return the oldConfiguration
     */
    @XmlElement
    public final String getOldConfiguration() {
        return this.oldConfiguration;
    }

    /**
     * @return the newConfiguration
     */
    @XmlElement
    public final String getNewConfiguration() {
        return this.newConfiguration;
    }

    /**
     * @param oldConfiguration the oldConfiguration to set
     */
    protected final void setOldConfiguration(String oldConfiguration) {
        this.oldConfiguration = oldConfiguration;
    }

    /**
     * @param newConfiguration the newConfiguration to set
     */
    protected final void setNewConfiguration(String newConfiguration) {
        this.newConfiguration = newConfiguration;
    }
    
   /*
    * (non-Javadoc)
    * @see java.lang.Object#toString()
    */
  public String toString() {
     
     StringBuilder sb = new StringBuilder();
     sb.append("{");
     sb.append(this.getClass().getSimpleName());
     sb.append(": oldConfiguration: ");
     sb.append(this.oldConfiguration);
     sb.append(", newConfiguration: ");
     sb.append(this.newConfiguration);
     sb.append(", ");
     super.toString(sb);
     sb.append("}");
     return sb.toString();
  }

 /**
   * 
   * @param configuration
   * @return
   */
  private String cleanConfigurationForDisplay(Map<String, String> configuration) {
      
      StringBuilder sb = new StringBuilder();
      sb.append("[");
      Iterator<String> iterator = configuration.keySet().iterator();
      while (iterator.hasNext()) {
          String key = iterator.next();
          String displayValue = null;
          if (key.toLowerCase().indexOf("password") >= 0) {
              displayValue = "PROTECTED_VALUE";
          } else {
              displayValue = configuration.get(key);
          }
          sb.append(key);
          sb.append("=");
          sb.append(displayValue);
          if (iterator.hasNext()) {
              sb.append(", ");
          }
      }
      sb.append("]");
      return sb.toString();
  }
}