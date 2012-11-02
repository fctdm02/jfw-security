/**
* These materials contain confidential information and 
* trade secrets of Compuware Corporation. You shall 
* maintain the materials as confidential and shall not 
* disclose its contents to any third party except as may 
* be required by law or regulation. Use, disclosure, 
* or reproduction is prohibited without the prior express 
* written permission of Compuware Corporation.
* 
* All Compuware products listed within the materials are 
* trademarks of Compuware Corporation. All other company 
* or product names are trademarks of their respective owners.
* 
* Copyright (c) 2010 Compuware Corporation. All rights reserved.
* 
*/
package com.compuware.frameworks.security.service.api.authorization;

import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;

/**
 * 
 * @author tmyers
 *
 */
public interface IAclManagerService {
	
	/**
	 * 
	 * @param securedObject
	 * @param permission
	 * @param clazz
	 */
	void addPermission(
			IAclDomainObject securedObject, 
			Permission permission, 
			Class<?> clazz);
	
	/**
	 * 
	 * @param securedObject
	 * @param recipient
	 * @param permission
	 * @param clazz
	 */
	void addPermission(
			IAclDomainObject securedObject, 
			Sid recipient, 
			Permission permission, 
			Class<?> clazz);

	/**
	 * 
	 * Recipient here should be the name of either a user or a group.
	 * 
	 * @param securedObject
	 * @param recipient
	 * @param permission
	 * @param clazz
	 */
	void addPermission(
			IAclDomainObject securedObject, 
			String recipient, 
			Permission permission, 
			Class<?> clazz);
	
	/**
	 * 
	 * @param securedObject
	 * @param recipient
	 * @param permission
	 * @param clazz
	 */
	void deletePermission(
			IAclDomainObject securedObject, 
			Sid recipient, 
			Permission permission,
			Class<?> clazz);
}