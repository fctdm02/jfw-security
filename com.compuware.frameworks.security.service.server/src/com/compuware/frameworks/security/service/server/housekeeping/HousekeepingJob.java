/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2010 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.server.housekeeping;

import java.util.Calendar;

import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.scheduling.quartz.QuartzJobBean;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import com.compuware.frameworks.security.persistence.PersistenceProvider;
import com.compuware.frameworks.security.persistence.dao.IAclSql;

/**
 * 
 * @author tmyers
 */
public final class HousekeepingJob extends QuartzJobBean {
    
    /* */
    private Logger logger = Logger.getLogger(HousekeepingJob.class);
    
    /* */
    private int maxAgeInDays = 90;
    
    /**
     * 
     */
    public HousekeepingJob() {
        
    }
    
    /**
     * @return the maxAgeInDays
     */
    public final int getMaxAgeInDays() {
        return maxAgeInDays;
    }

    /**
     * @param maxAgeInDays the maxAgeInDays to set
     */
    public final void setMaxAgeInDays(int maxAgeInDays) {
        this.maxAgeInDays = maxAgeInDays;
    }
    
    /*
     * (non-Javadoc)
     * @see org.springframework.scheduling.quartz.QuartzJobBean#executeInternal(org.quartz.JobExecutionContext)
     */
    protected void executeInternal(JobExecutionContext context) throws JobExecutionException {
        
        logger.info("Running housekeeping job...");
        try {
			runJob();
		} catch (InterruptedException e) {
			throw new JobExecutionException("Failure running housekeeping job", e);
		}        
    }

    /**
     * @throws InterruptedException 
     * 
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void runJob() throws InterruptedException {
        
        final DataSource dataSource = PersistenceProvider.getInstance().getSecurityDataSourceWrapper().getDataSource();
        final IAclSql sql = PersistenceProvider.getInstance().getAclSql();
        final JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        final TransactionTemplate transactionTemplate = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        transactionTemplate.execute(new TransactionCallback() {
            public Object doInTransaction(TransactionStatus arg0) {
                
                Calendar currentTime = Calendar.getInstance();
                int currentYear = currentTime.get(Calendar.YEAR);
                int currentDayInYear = currentTime.get(Calendar.DAY_OF_YEAR);

                Calendar thresholdTime = Calendar.getInstance();
                if (currentDayInYear > maxAgeInDays) {
                    thresholdTime.set(Calendar.DAY_OF_YEAR, currentDayInYear - maxAgeInDays);
                } else {
                    thresholdTime.set(Calendar.YEAR, currentYear - 1);
                    int delta = maxAgeInDays - currentDayInYear;
                    thresholdTime.set(Calendar.DAY_OF_YEAR, 365 - delta);
                }
                
                int thresholdYear = thresholdTime.get(Calendar.YEAR);                
                int thresholdMonth = thresholdTime.get(Calendar.MONTH) + 1;
                int thresholdDayOfMonth = thresholdTime.get(Calendar.DAY_OF_MONTH);

                StringBuilder sb = new StringBuilder();
                sb.append(thresholdYear);
                sb.append("-");
                if (thresholdMonth < 10) {
                    sb.append("0");
                }
                sb.append(thresholdMonth);
                sb.append("-");
                if (thresholdDayOfMonth < 10) {
                    sb.append("0");
                }
                sb.append(thresholdDayOfMonth);
                
                String query = sql.getDeleteOldAuditEventSql();
                query = query.replace("{0}", sb.toString());
                                
                logger.info("Purging old audit event records with: " + query);
                jdbcTemplate.execute(query);
                
                return null;
            }
        });
    }
}