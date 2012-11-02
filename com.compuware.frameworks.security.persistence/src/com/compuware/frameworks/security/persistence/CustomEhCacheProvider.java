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
package com.compuware.frameworks.security.persistence;

import java.util.Properties;

import net.sf.ehcache.CacheManager;

import org.apache.log4j.Logger;
import org.hibernate.cache.Cache;
import org.hibernate.cache.CacheException;
import org.hibernate.cache.CacheProvider;
import org.hibernate.cache.Timestamper;

/**
 * @author tmyers
 */
@SuppressWarnings("deprecation")
public final class CustomEhCacheProvider implements CacheProvider {

    /* */
    private final Logger logger = Logger.getLogger(CustomEhCacheProvider.class);

    /* */
    private static CacheManager cacheManager;
    
    /**
     * 
     */
    public CustomEhCacheProvider() {
        
    }
    
    /**
     * 
     * @param cacheManager
     */
    public static void setCacheManager(CacheManager cacheManager) {
        CustomEhCacheProvider.cacheManager = cacheManager;
    }

    /**
     * @param name
     * @param properties
     * @return Cache
     * @throws CacheException
     */
    public Cache buildCache(String name, Properties properties) throws CacheException {
        try {
            net.sf.ehcache.Ehcache cache = CustomEhCacheProvider.cacheManager.getEhcache(name);
            if (cache == null) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Unable to find EhCache configuration for cache named: [" + name + "]. Using defaults.");
                }
                CustomEhCacheProvider.cacheManager.addCache(name);
                cache = CustomEhCacheProvider.cacheManager.getEhcache(name);
                if (logger.isDebugEnabled()) {
                    logger.debug("Started EhCache region: [" + name + "].");
                }
            }
            return new net.sf.ehcache.hibernate.EhCache(cache);
        } catch (net.sf.ehcache.CacheException e) {
            throw new CacheException(e);
        }
    }

    /**
     * @return long
     */
    public long nextTimestamp() {
        return Timestamper.next();
    }

    /**
     * @param properties
     * @throws CacheException
     */
    public void start(Properties properties) throws CacheException {
    }

    /**
     * 
     */
    public void stop() {
    }

    /**
     * @return boolean
     */
    public boolean isMinimalPutsEnabledByDefault() {
        return false;
    }
}