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
package com.compuware.frameworks.security.persistence.dao.hibernate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;

import com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao;
import com.compuware.frameworks.security.service.api.management.exception.ObjectAlreadyExistsException;
import com.compuware.frameworks.security.service.api.model.DomainObjectFactory;
import com.compuware.frameworks.security.service.api.model.MigrationRecord;
import com.compuware.frameworks.security.service.api.model.MultiTenancyRealm;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 */
public final class MigrationRecordHibernateDao extends BaseHibernateDao implements IMigrationRecordDao {

    /* */
    private final Logger logger = Logger.getLogger(MigrationRecordHibernateDao.class);
    
    /**
     * 
     * @param sessionFactory
     */
    public MigrationRecordHibernateDao(SessionFactory sessionFactory) {
    	super(sessionFactory);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao#migrationRecordExists(com.compuware.frameworks.security.service.api.model.MigrationRecord)
     */
    public boolean migrationRecordExists(MigrationRecord migrationRecord) {
                        
        @SuppressWarnings(RAW_TYPES)
        List list = this.sessionFactory.getCurrentSession()
        .createQuery(FROM + MIGRATION_RECORD + " migrationRecord where migrationRecord.sourceRepositoryName=? and migrationRecord.principalType=? and migrationRecord.principalName=? and migrationRecord.reason=? and migrationRecord.creationDate=? and migrationRecord.multiTenancyRealm=?")
        .setCacheable(false)
        .setParameter(0, migrationRecord.getSourceRepositoryName())
        .setParameter(1, migrationRecord.getPrincipalType())
        .setParameter(2, migrationRecord.getPrincipalName())
        .setParameter(3, migrationRecord.getReason())
        .setParameter(4, migrationRecord.getCreationDate())
        .setParameter(5, migrationRecord.getMultiTenancyRealm())
        .list();
        
        if (list.size() == 0) {
            return false;
        }
        return true;
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao#createUserMigrationRecord(java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
	public MigrationRecord createUserMigrationRecord(
	    String sourceRepositoryName,
	    String principalName,
	    String nameValuePairs,
	    String reason,
	    MultiTenancyRealm multiTenancyRealm)
	throws 
	    ObjectAlreadyExistsException, 
	    ValidationException {
		
		MigrationRecord migrationRecord = new DomainObjectFactory().createMigrationRecord(
				sourceRepositoryName,
				MigrationRecord.USER,
				principalName, 
				nameValuePairs, 
				reason,
				multiTenancyRealm);
		
		if (migrationRecordExists(migrationRecord)) {
		    migrationRecord.setCreationDate(System.currentTimeMillis() + 1000);
		}
		
        if (!migrationRecordExists(migrationRecord)) {
            logger.info("Creating migration record: " + migrationRecord);
            this.sessionFactory.getCurrentSession().save(migrationRecord);
        } else {
            logger.error("Could not create migration record: [" + migrationRecord.getNaturalIdentity() + "] because one already exists with the same identity.");    
        }
		
		return migrationRecord;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao#createGroupMigrationRecord(java.lang.String, java.lang.String, java.lang.String, java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
    public MigrationRecord createGroupMigrationRecord(
        String sourceRepositoryName,
        String principalName,
        String nameValuePairs,
        String reason,
        MultiTenancyRealm multiTenancyRealm)
    throws 
        ObjectAlreadyExistsException, 
        ValidationException {
        
        MigrationRecord migrationRecord = new DomainObjectFactory().createMigrationRecord(
                sourceRepositoryName,
                MigrationRecord.GROUP,
                principalName, 
                nameValuePairs, 
                reason,
                multiTenancyRealm);
        
        if (!migrationRecordExists(migrationRecord)) {
            logger.info("Creating migration record: " + migrationRecord);
            this.sessionFactory.getCurrentSession().save(migrationRecord);
        } else {
            logger.error("Could not create migration record: [" + migrationRecord.getNaturalIdentity() + "] because one already exists with the same identity.");    
        }
        
        this.sessionFactory.getCurrentSession().save(migrationRecord);
        
        return migrationRecord;
    }
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao#getAllMigrationRecords(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
	 */
	@SuppressWarnings("unchecked")
	public List<MigrationRecord> getAllMigrationRecords(
		MultiTenancyRealm multiTenancyRealm) {
		
        return this.sessionFactory.getCurrentSession()
        	.createQuery(FROM + MIGRATION_RECORD + " migrationRecord where migrationRecord.multiTenancyRealm=?")
        	.setParameter(0, multiTenancyRealm)
        	.setCacheable(true)
        	.setCacheRegion("com.compuware.frameworks.security.persistence.MigrationRecords")
            .setMaxResults(MAX_RESULTS)
        	.list();
	}
	
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao#getMigrationRecordSourceRepositoryNames(com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    public List<String> getMigrationRecordSourceRepositoryNames(
        MultiTenancyRealm multiTenancyRealm) {
        
        ArrayList<String> sourceRepositoryNames = new ArrayList<String>();
        Collection<MigrationRecord> allMigrationRecords = this.getAllMigrationRecords(multiTenancyRealm);
        Iterator<MigrationRecord> iterator = allMigrationRecords.iterator();
        while (iterator.hasNext()) {
            MigrationRecord migrationRecord = iterator.next();
            String sourceRepositoryName = migrationRecord.getSourceRepositoryName();
            if (!sourceRepositoryNames.contains(sourceRepositoryName)) {
                sourceRepositoryNames.add(sourceRepositoryName);    
            }
        }
        return sourceRepositoryNames;
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao#getAllMigrationRecordsForSourceRepository(java.lang.String, com.compuware.frameworks.security.service.api.model.MultiTenancyRealm)
     */
    @SuppressWarnings("unchecked")
    public List<MigrationRecord> getAllMigrationRecordsForSourceRepository(
        String sourceRepositoryName, 
        MultiTenancyRealm multiTenancyRealm) {

        return this.sessionFactory.getCurrentSession()
        .createQuery(FROM + MIGRATION_RECORD + " migrationRecord where migrationRecord.multiTenancyRealm=? and migrationRecord.sourceRepositoryName=?")
        .setParameter(0, multiTenancyRealm)
        .setParameter(1, sourceRepositoryName)
        .setCacheable(true)
        .setCacheRegion("com.compuware.frameworks.security.persistence.MigrationRecords")
        .list();
    }
}