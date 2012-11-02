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

/**
 * 
 * @author dresser
 *
 */
@XmlRootElement
public final class CompuwareSecurityWSLdapImportResult {
	
    /* */
	private String shadowObjectName;
	
	/* */
	private String shadowImportError;
	
	/**
	 * 
	 */
	public CompuwareSecurityWSLdapImportResult() {
		setShadowObjectName(null);
		setShadowImportError(null);
	}

	/**
	 * 
	 * @param name
	 * @param e
	 */
	public CompuwareSecurityWSLdapImportResult(String name, String e ) {
		setShadowObjectName(name);
		setShadowImportError(e);
	}

	/**
	 * 
	 * @param shadowObjectName
	 */
	public void setShadowObjectName(String shadowObjectName) {
		this.shadowObjectName = shadowObjectName;
	}

	/**
	 * 
	 * @return
	 */
	@XmlElement
	public String getShadowObjectName() {
		return shadowObjectName;
	}

	/**
	 * 
	 * @param shadowImportException
	 */
	public void setShadowImportError(String shadowImportException) {
		this.shadowImportError = shadowImportException;
	}

	/**
	 * 
	 * @return
	 */
	@XmlElement
	public String getShadowImportError() {
		return shadowImportError;
	}
	
	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
	    return this.shadowObjectName + "=" + this.shadowImportError;
	}
}