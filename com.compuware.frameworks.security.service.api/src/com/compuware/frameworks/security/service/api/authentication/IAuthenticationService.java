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
package com.compuware.frameworks.security.service.api.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;

import com.compuware.frameworks.security.service.api.authentication.exception.AccountLockedException;
import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.authentication.exception.PasswordExpiredException;
import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;
import com.compuware.frameworks.security.service.api.model.CompuwareSecuritySession;
import com.compuware.frameworks.security.service.api.model.exception.MaxSessionsPerUserExceededException;

/**
 * 
 * @author tmyers
 *
 */
public interface IAuthenticationService extends AuthenticationManager, AuthenticationProvider {

    /** */
    String INVALID_CREDENTIALS_REASON = "INVALID_CREDENTIALS_REASON";
    
    /** */
    String PASSWORD_HAS_EXPIRED_REASON = "PASSWORD_HAS_EXPIRED_REASON";
    
    /** */
    String ACCOUNT_HAS_BEEN_DEACTIVATED_REASON = "ACCOUNT_HAS_BEEN_DEACTIVATED_REASON";

    /** */
    String ACCOUNT_HAS_NUMBER_INVALID_LOGINS_EXCEEDED_REASON = "ACCOUNT_HAS_NUMBER_INVALID_LOGINS_EXCEEDED_REASON";
    
    /** */
    String DUPLICATE_ACCOUNTS_IN_LDAP_AND_LOCAL_CSS_REASON = "DUPLICATE_ACCOUNTS_IN_LDAP_AND_LOCAL_CSS_REASON";
    
    /** */
    String MISSING_ORIGINATING_IP_ADDRESS_IN_REQUEST_REASON = "MISSING_ORIGINATING_IP_ADDRESS_IN_REQUEST_REASON"; 
    
    /** */
    String MISSING_ORIGINATING_HOSTNAME_IN_REQUEST_REASON = "MISSING_ORIGINATING_HOSTNAME_IN_REQUEST_REASON"; 
    
   /**
    * Authenticates the User represented by username in the given realm.
    * 
    * @param username
    * @param clearTextPassword
    * @param realmName
    * @param originatingIpAddress
    * @param originatingHostname
    * @return CompuwareSecurityAuthenticationToken
    * @throws InvalidCredentialsException thrown if username/password combination is not valid.
    * @throws AccountLockedException thrown if the user authenticates successfully, but the account is marked as locked.
    * @throws PasswordExpiredException thrown if the user authenticates successfully, but the user password has expired.
    */
   CompuwareSecurityAuthenticationToken authenticate(
	   String username, 
	   ClearTextPassword clearTextPassword, 
	   String realmName, 
	   String originatingIpAddress, 
	   String originatingHostname)
   throws 
       InvalidCredentialsException, 
       AccountLockedException, 
       PasswordExpiredException;
    
  /**
   * Authenticates using the given <code>IAuthenticationCredentialCollector</code>, 
   * which is used to extract the credentials of the user.  Depending upon the 
   * implementation, the user may or may not be prompted for their login credentials.
   * 
   * @param authenticationCredentialCollector
   * @param realmName
   * @param originatingIpAddress
   * @param originatingHostname
   * @return Authentication
   * @throws InvalidCredentialsException thrown if username/password combination is not valid.
   * @throws AccountLockedException thrown if the user authenticates successfully, but the account is marked as locked.
   * @throws PasswordExpiredException thrown if the user authenticates successfully, but the user password has expired.
   */
   CompuwareSecurityAuthenticationToken authenticate(
      IAuthenticationCredentialCollector authenticationCredentialCollector,
	  String realmName, 
	  String originatingIpAddress, 
	  String originatingHostname)
  throws 
      InvalidCredentialsException, 
      AccountLockedException, 
      PasswordExpiredException;
  
  /**
   * a.k.a. "logout"
   * 
   * Removes the Authentication associated with the thread from the SecurityContext.
   */
  void deauthenticate();
  
  /**
   * Convenience method for combining methods in the authentication and session services.
   * <p>
   * @param username The unique identifier of the user 
   * @param clearTextPassword A secret password that only the user in question should know.
   * @param realmName
   * @param originatingIpAddress The IP Address of the workstation where the user agent (browser) or thick-client resides.
   * @param originatingHostname The hostname of the workstation where the user agent (browser) or thick-client resides.
   * 
   * @return The <code>CompuwareSecuritySession</code> that was created upon successful authentication of the user 
   * given by <code>username</code> and <code>password</code>.  This session ID is a randomly generated number.
   * 
   * @throws InvalidCredentialsException If the combination of <code>username</code> and
   * <code>password</code> are invalid for authentication. 
   * @throws AccountLockedException If the user identified by <code>username</code> has had
   * their account locked (because of too many invalid login attempts).  The only recourse in
   * this scenario is to have a user with administrative privileges perform a <b>password reset</b>
   * @throws PasswordExpiredException A user's credentials were acceptable, except that the user's
   * password was expired and they must change it immediately. 
   * @throws MaxSessionsPerUserExceededException A user's credentials were acceptable, except that
   * the number of open sessions for that user has been exceeded.
   */
  CompuwareSecuritySession authenticateWithSessionCreation(
      String username, 
      ClearTextPassword clearTextPassword, 
      String realmName,
      String originatingIpAddress, 
      String originatingHostname) 
  throws 
      InvalidCredentialsException, 
      AccountLockedException, 
      PasswordExpiredException,
      MaxSessionsPerUserExceededException;
}