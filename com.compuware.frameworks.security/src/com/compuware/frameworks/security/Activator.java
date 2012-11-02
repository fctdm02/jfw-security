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
package com.compuware.frameworks.security;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

/**
 * 
 */
public class Activator implements BundleActivator {
	
	/* */
	private static String bundleName;
	
	/* */
	private static String bundleVersion;

	/*
	 * (non-Javadoc)
	 * @see org.osgi.framework.BundleActivator#start(org.osgi.framework.BundleContext)
	 */
	public final void start(BundleContext context) {
		
		Bundle bundle = context.getBundle();
		Activator.bundleName = bundle.getSymbolicName();
		Activator.bundleVersion = bundle.getVersion().toString();
	}

	/*
	 * (non-Javadoc)
	 * @see org.osgi.framework.BundleActivator#stop(org.osgi.framework.BundleContext)
	 */
	public final void stop(BundleContext context) {
	}
	
	/**
	 * 
	 * @return
	 */
	public static final String getBundleVersion() {
		return Activator.bundleVersion;
	}
	
	/**
	 * 
	 * @return
	 */
	public static final String getBundleName() {
		return Activator.bundleName;
	}
	
}
