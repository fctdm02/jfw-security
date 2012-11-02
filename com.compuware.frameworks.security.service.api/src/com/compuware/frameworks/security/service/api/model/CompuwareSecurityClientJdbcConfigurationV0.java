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

@XmlRootElement
public class CompuwareSecurityClientJdbcConfigurationV0 {

	private String databaseType;
	private String hostname;
	private String port;
	private String databaseName;
	private String instanceName;
	private boolean trusted;
	private String sqlLogin;
	private String sqlPassword;
	
	public CompuwareSecurityClientJdbcConfigurationV0() {
		databaseType = "";
		hostname = "";
		port = "";
		instanceName = "";
		trusted = true;
		sqlLogin = "";
		sqlPassword = "";
	}
	
	public void setDatabaseType(String databaseType) {
		this.databaseType = databaseType;
	}
	@XmlElement
	public String getDatabaseType() {
		return databaseType;
	}
	
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}
	@XmlElement
	public String getHostname() {
		return hostname;
	}
	
	public void setPort(String port) {
		this.port = port;
	}
	@XmlElement
	public String getPort() {
		return port;
	}
	
	public void setDatabaseName(String databaseName) {
		this.databaseName = databaseName;
	}

	@XmlElement
	public String getDatabaseName() {
		return databaseName;
	}

	public void setInstanceName(String instanceName) {
		this.instanceName = instanceName;
	}
	@XmlElement
	public String getInstanceName() {
		return instanceName;
	}
	
	public void setTrusted(boolean trusted) {
		this.trusted = trusted;
	}
	@XmlAttribute
	public boolean isTrusted() {
		return trusted;
	}
	
	public void setSqlLogin(String sqlLogin) {
		this.sqlLogin = sqlLogin;
	}
	@XmlElement
	public String getSqlLogin() {
		return sqlLogin;
	}
	
	public void setSqlPassword(String sqlPassword) {
		this.sqlPassword = sqlPassword;
	}
	@XmlElement
	public String getSqlPassword() {
		return sqlPassword;
	}
}
