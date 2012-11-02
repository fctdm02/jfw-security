package com.compuware.frameworks.security.persistence.dao.hibernate;

import org.hibernate.SessionFactory;

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

/**
 * 
 * @author tmyers
 */
class HibernateDaoFactory {

	/**
	 * 
	 * @param sessionFactory
	 * @return
	 */
	AuditEventHibernateDao createAuditEventHibernateDao(SessionFactory sessionFactory) {
		
		return new AuditEventHibernateDao(sessionFactory);
	}
	
	/**
	 * 
	 * @param sessionFactory
	 * @return
	 */
	MultiTenancyRealmHibernateDao createMultiTenancyRealmHibernateDao(SessionFactory sessionFactory) {
		
		return new MultiTenancyRealmHibernateDao(sessionFactory);
	}

	/**
	 * 
	 * @param sessionFactory
	 * @return
	 */
	SecurityPrincipalHibernateDao createSecurityPrincipalHibernateDao(SessionFactory sessionFactory) {
		
		return new SecurityPrincipalHibernateDao(sessionFactory);
	}

	/**
	 * 
	 * @param sessionFactory
	 * @return
	 */
	SecurityRoleHibernateDao createSecurityRoleHibernateDao(SessionFactory sessionFactory) {
		
		return new SecurityRoleHibernateDao(sessionFactory);
	}
}