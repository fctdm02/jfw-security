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

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author dresser
 *
 */
@XmlRootElement
public class CompuwareSecurityClientLdapConfiguration {
	
	// ----------------------------------------------------------------------------------------------
	// Ldap service
	private String serverType;
	private boolean isEnabled;
	private String referral;
	private String referralLimit;
	
	// ----------------------------------------------------------------------------------------------
	// Connection
	private String hostname;
	private String port;
	private String encryptionMethod;
	private String baseDN;
	private String serviceAccountUsername;
	private String serviceAccountPassword;
	private String connectionTimeout;
	
	// ----------------------------------------------------------------------------------------------
	// Users
	private String userSearchBase;
	private String userSearchFilter;
	private String searchBaseForUsersGroups;
	private String searchFilterForUsersGroups;
	private String usernameAttribute;
	private String emailAttribute;
	private String firstnameAttribute;
	private String lastnameAttribute;
	
	// ----------------------------------------------------------------------------------------------
	// Groups
	private String groupSearchBase;
	private String groupSearchFilter;
	private String groupnameAttribute;
	private String groupDescriptionAttribute;

	// ----------------------------------------------------------------------------------------------
	// Ldap service
	public final void setEnabled(boolean isEnabled) {
		this.isEnabled = isEnabled;
	}

	@XmlAttribute
	public final boolean isEnabled() {
		return isEnabled;
	}
	
	public final void setReferral(String referral) {
		this.referral = referral;
	}

	@XmlElement
	public final String getReferral() {
		return referral;
	}

	public final void setReferral_limit(String rlimit) {
		this.referralLimit = rlimit;
	}

	@XmlElement
	public final String getReferral_limit() {
		return referralLimit;
	}

	public final void setServerType(String serverType) {
		this.serverType = serverType;
	}

	@XmlElement
	public final String getServerType() {
		return serverType;
	}

	// ----------------------------------------------------------------------------------------------
	// Connection
	public final void setHostname(String hostname) {
		this.hostname = hostname;
	}
	
	@XmlElement
	public final String getHostname() {
		return hostname;
	}

	public final void setPort(String port) {
		this.port = port;
	}

	@XmlElement
	public final String getPort() {
		return port;
	}

	public final void setEncryptionMethod(String encryptionParm) {
		this.encryptionMethod = encryptionParm;
	}

	@XmlElement
	public final String getEncryptionMethod() {
		return encryptionMethod;
	}

	public final void setBaseDN(String baseDN) {
		this.baseDN = baseDN;
	}

	@XmlElement
	public final String getBaseDN() {
		return baseDN;
	}

	public final void setServiceAccountUsername(String serviceAccountUsername) {
		this.serviceAccountUsername = serviceAccountUsername;
	}

	@XmlElement
	public final String getServiceAccountUsername() {
		return serviceAccountUsername;
	}

	public final void setServiceAccountPassword(String serviceAccountPassword) {
		this.serviceAccountPassword = serviceAccountPassword;
	}

	@XmlElement
	public final String getServiceAccountPassword() {
		return serviceAccountPassword;
	}

	/**
	 * 
	 * @param connectionTimeout in milliseconds
	 */
	public final void setConnectionTimeout(String connectionTimeout) {
		this.connectionTimeout = connectionTimeout;
	}

	/**
	 * 
	 * @return timeout integer number of milliseconds as a string
	 */
	@XmlElement
	public final String getConnectionTimeout() {
		return connectionTimeout;
	}

	// ----------------------------------------------------------------------------------------------
	// Users
	public final void setUserSearchBase(String userSearchBase) {
		this.userSearchBase = userSearchBase;
	}

	@XmlElement
	public final String getUserSearchBase() {
		return userSearchBase;
	}

	public final void setUserSearchFilter(String userSearchFilter) {
		this.userSearchFilter = userSearchFilter;
	}

	@XmlElement
	public final String getUserSearchFilter() {
		return userSearchFilter;
	}

	public final void setSearchBaseForUsersGroups(String searchBaseForUsersGroups) {
		this.searchBaseForUsersGroups = searchBaseForUsersGroups;
	}

	@XmlElement
	public final String getSearchBaseForUsersGroups() {
		return searchBaseForUsersGroups;
	}

	public final void setSearchFilterForUsersGroups(String searchFilterForUsersGroups) {
		this.searchFilterForUsersGroups = searchFilterForUsersGroups;
	}

	@XmlElement
	public final String getSearchFilterForUsersGroups() {
		return searchFilterForUsersGroups;
	}

	public final void setUsernameAttribute(String usernameAttribute) {
		this.usernameAttribute = usernameAttribute;
	}

	@XmlElement
	public final String getUsernameAttribute() {
		return usernameAttribute;
	}

	public final void setEmailAttribute(String emailAttribute) {
		this.emailAttribute = emailAttribute;
	}

	@XmlElement
	public final String getEmailAttribute() {
		return emailAttribute;
	}

	public final void setFirstnameAttribute(String firstnameAttribute) {
		this.firstnameAttribute = firstnameAttribute;
	}

	@XmlElement
	public final String getFirstnameAttribute() {
		return firstnameAttribute;
	}

	public final void setLastnameAttribute(String lastnameAttribute) {
		this.lastnameAttribute = lastnameAttribute;
	}

	@XmlElement
	public final String getLastnameAttribute() {
		return lastnameAttribute;
	}

	// ----------------------------------------------------------------------------------------------
	// Groups
	public final void setGroupSearchBase(String groupSearchBase) {
		this.groupSearchBase = groupSearchBase;
	}

	@XmlElement
	public final String getGroupSearchBase() {
		return groupSearchBase;
	}

	public final void setGroupSearchFilter(String groupSearchFilter) {
		this.groupSearchFilter = groupSearchFilter;
	}

	@XmlElement
	public final String getGroupSearchFilter() {
		return groupSearchFilter;
	}

	public final void setGroupnameAttribute(String groupnameAttribute) {
		this.groupnameAttribute = groupnameAttribute;
	}

	@XmlElement
	public final String getGroupnameAttribute() {
		return groupnameAttribute;
	}

	public final void setGroupDescriptionAttribute(String groupDescriptionAttribute) {
		this.groupDescriptionAttribute = groupDescriptionAttribute;
	}

	@XmlElement
	public final String getGroupDescriptionAttribute() {
		return groupDescriptionAttribute;
	}
		
	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public final String toString() {
	
	    StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(this.getClass().getSimpleName());
        sb.append(": isEnabled=");
        sb.append(this.isEnabled);
        sb.append(", encryptionMethod=");
        sb.append(this.encryptionMethod);        
        sb.append(", hostname=");
        sb.append(this.hostname);
        sb.append(", port=");
        sb.append(this.port);
        sb.append(", baseDN=");
        sb.append(this.baseDN);
        sb.append(", referral=");
        sb.append(this.referral);
        sb.append(", referralLimit=");
        sb.append(this.referralLimit);
        sb.append(", serviceAccountUsername=");
        sb.append(this.serviceAccountUsername);
        sb.append(", serviceAccountPassword=[PROTECTED]");
        sb.append(", connectionTimeout=");
        sb.append(this.connectionTimeout);
        sb.append(", userSearchBase=");
        sb.append(this.userSearchBase);
        sb.append(", userSearchFilter=");
        sb.append(this.userSearchFilter);
        sb.append(", searchBaseForUsersGroups=");
        sb.append(this.searchBaseForUsersGroups);
        sb.append(", searchFilterForUsersGroups=");
        sb.append(this.searchFilterForUsersGroups);
        sb.append(", usernameAttribute=");
        sb.append(this.usernameAttribute);
        sb.append(", emailAttribute=");
        sb.append(this.emailAttribute);
        sb.append(", firstnameAttribute=");
        sb.append(this.firstnameAttribute);
        sb.append(", lastnameAttribute=");
        sb.append(this.lastnameAttribute);
        sb.append(", groupSearchBase=");
        sb.append(this.groupSearchBase);
        sb.append(", groupSearchFilter=");
        sb.append(this.groupSearchFilter);
        sb.append(", groupnameAttribute=");
        sb.append(this.groupnameAttribute);
        sb.append(", groupDescriptionAttribute=");
        sb.append(this.groupDescriptionAttribute);
        sb.append("}");	    
	    return sb.toString();
	}
}
