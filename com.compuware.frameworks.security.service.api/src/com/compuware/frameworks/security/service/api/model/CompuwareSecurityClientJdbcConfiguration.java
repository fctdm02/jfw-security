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

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.compuware.frameworks.security.service.api.configuration.IJdbcConfiguration;

/**
 * 
 * @author dresser
 *
 */
@XmlRootElement
public class CompuwareSecurityClientJdbcConfiguration {
    
    /* */
	private String databaseType;
	
	/* */
	private String hostname;
	
	/* */
	private String port;
	
	/* */
	private String databaseName;
	
	/* */
	private String dbAuthType;
	
	/* */
	private String windowsDomain;
	
	/* */
	private String username;
	
	/* */
	private String password;
	
	/* */
	private String additionalConnectionStringProperties;

	/**
	 * 
	 */
	public CompuwareSecurityClientJdbcConfiguration() {
	    
		setDatabaseType(IJdbcConfiguration.SQLSERVER);
		setHostname("");
		setPort("");
		setDatabaseName("");
		setDbAuthType(IJdbcConfiguration.LOCAL_DB_AUTH_TYPE);
		setWindowsDomain("");
		setUsername("");
		setPassword("");
		setAdditionalConnectionStringProperties("");
	}
	
	/**
	 * 
	 * @param databaseType
	 * @param hostname
	 * @param port
	 * @param databaseName
	 * @param dbAuthType
	 * @param windowsDomain
	 * @param username
	 * @param password
	 * @param additionalConnectionStringProperties
	 */
	public CompuwareSecurityClientJdbcConfiguration(
        String databaseType,
        String hostname,
        String port,
        String databaseName,
        String dbAuthType,
        String windowsDomain,
        String username,
        String password,
        String additionalConnectionStringProperties) {
	    
        setDatabaseType(databaseType);
        setHostname(hostname);
        setPort(port);
        setDatabaseName(databaseName);
        setDbAuthType(dbAuthType);
        setWindowsDomain(windowsDomain);
        setUsername(username);
        setPassword(password);
        setAdditionalConnectionStringProperties(additionalConnectionStringProperties);
	}
	
	/**
	 * 
	 * @param databaseType
	 */
	public final void setDatabaseType(String databaseType) {
		this.databaseType = databaseType;
	}
	
	/**
	 * 
	 * @return
	 */
	@XmlElement
	public final String getDatabaseType() {
		return databaseType;
	}
	
	/**
	 * 
	 * @param hostname
	 */
	public final void setHostname(String hostname) {
		this.hostname = hostname;
	}
	
	/**
	 * 
	 * @return
	 */
	@XmlElement
	public final String getHostname() {
		return hostname;
	}
	
	/**
	 * 
	 * @param port
	 */
	public final void setPort(String port) {
		this.port = port;
	}

	/**
	 * 
	 * @return
	 */
	@XmlElement
	public final String getPort() {
		return port;
	}

	/**
	 * 
	 * @param databaseName
	 */
	public final void setDatabaseName(String databaseName) {
		this.databaseName = databaseName;
	}

	/**
	 * 
	 * @return
	 */
	@XmlElement
	public final String getDatabaseName() {
		return databaseName;
	}
	
	/**
	 * 
	 * @param dbAuthType
	 */
	public final void setDbAuthType(String dbAuthType) {
		this.dbAuthType = dbAuthType;
	}
	
	/**
	 * 
	 * @return
	 */
	@XmlElement
	public final String getDbAuthType() {
		return this.dbAuthType;
	}
		
	/**
	 * 
	 * @param windowsDomain
	 */
	public final void setWindowsDomain(String windowsDomain) {
		this.windowsDomain = windowsDomain;
	}
	
	/**
	 * 
	 * @return
	 */
	@XmlElement
	public final String getWindowsDomain() {
	    return this.windowsDomain;
	}
		
    /**
     * 
     * @param username
     */
    public final void setUsername(String username) {
        this.username = username;
    }
    
    /**
     * 
     * @return
     */
    @XmlElement
    public final String getUsername() {
        return this.username;
    }
	
    /**
     * 
     * @param password
     */
    public final void setPassword(String password) {
        this.password = password;
    }
    
    /**
     * 
     * @return
     */
    @XmlElement
    public final String getPassword() {
        return this.password;
    }
	
    /**
     * 
     * @param additionalConnectionStringProperties
     */
    public final void setAdditionalConnectionStringProperties(String additionalConnectionStringProperties) {
        this.additionalConnectionStringProperties = additionalConnectionStringProperties;
    }
    
    /**
     * 
     * @return
     */
    @XmlElement
    public final String getAdditionalConnectionStringProperties() {
        return this.additionalConnectionStringProperties;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public final String toString() {
        
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(this.getClass().getSimpleName());
        sb.append(": databaseType=");
        sb.append(this.databaseType);
        sb.append(", hostname=");
        sb.append(this.hostname);
        sb.append(", port=");
        sb.append(this.port);
        sb.append(", databaseName=");
        sb.append(this.databaseName);
        sb.append(", dbAuthType=");
        sb.append(this.dbAuthType);
        sb.append(", windowsDomain=");
        sb.append(this.windowsDomain);
        sb.append(", username=");
        sb.append(this.username);
        sb.append(", password=[PROTECTED]");
        sb.append(", additionalConnectionStringProperties=");
        sb.append(this.additionalConnectionStringProperties);
        sb.append("}");
        return sb.toString();
    }
}
