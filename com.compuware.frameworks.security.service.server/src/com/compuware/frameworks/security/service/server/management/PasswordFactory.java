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
package com.compuware.frameworks.security.service.server.management;

import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;

import com.compuware.frameworks.security.service.api.model.ClearTextPassword;
import com.compuware.frameworks.security.service.api.model.DomainObject;
import com.compuware.frameworks.security.service.api.model.Password;
import com.compuware.frameworks.security.service.api.model.exception.PasswordPolicyException;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;
import com.compuware.frameworks.security.service.server.ServiceProvider;

/**
 * 
 * @author tmyers
 *
 */
class PasswordFactory {

    /**
     * 
     */
    public PasswordFactory() {
        
    }

    /**
     * 
     * @param clearTextPasswordParm
     * @return
     * @throws ValidationException
     */
    String encodePassword(ClearTextPassword clearTextPasswordParm) throws ValidationException {

        String encodedPassword = null;
        
        if (clearTextPasswordParm == null) {
            throw new ValidationException(ValidationException.FIELD_PASSWORD, ValidationException.REASON_CANNOT_BE_NULL);
        }
        String clearTextPassword = clearTextPasswordParm.getClearTextPassword();

        // TDM: If I had to list anything as a "hack", this would be it.
        if (!clearTextPassword.isEmpty()) {
            
            LdapShaPasswordEncoder shaPasswordEncoder = new LdapShaPasswordEncoder();
            
            byte[] salt = "jfwSecurity620".getBytes();
            encodedPassword = shaPasswordEncoder.encodePassword(clearTextPassword, salt);
            
        } else {
            
            // This is to support GDANSK, which effectively negates having security in the first place if we allow blank passwords.
            encodedPassword = DomainObject.ORACLE_EMPTY_STRING_ID;
        }
        
        return encodedPassword;
    }

    /**
     * 
     * @param newClearTextPassword
     * @param newClearTextPasswordVerify
     * @param minPasswordLength If -1, then there is no minimum required length check.
     * @param creationDate
     * @return Password
     * @throws ValidationException 
     */
    Password createPassword(
        ClearTextPassword newClearTextPassword,
        ClearTextPassword newClearTextPasswordVerify,
        int minPasswordLength,
        Long creationDate) 
    throws 
        PasswordPolicyException, 
        ValidationException {
        
        boolean isPasswordExpired = false;
        return createPassword(
            newClearTextPassword,
            newClearTextPasswordVerify,
            minPasswordLength,
            creationDate,
            isPasswordExpired);
    }
    
    /**
     * 
     * @param newClearTextPasswordParm
     * @param newClearTextPasswordVerifyParm
     * @param minPasswordLength If -1, then there is no minimum required length check.
     * @param creationDate
     * @param isPasswordExpired
     * @return Password
     * @throws ValidationException 
     */
    Password createPassword(
        ClearTextPassword newClearTextPasswordParm,
        ClearTextPassword newClearTextPasswordVerifyParm,
        int minPasswordLength,
        Long creationDate,
        boolean isPasswordExpired) 
    throws 
        PasswordPolicyException, 
        ValidationException {

        if (newClearTextPasswordParm == null) {
            throw new ValidationException(ValidationException.FIELD_PASSWORD, ValidationException.REASON_CANNOT_BE_NULL);
        }
        
        if (newClearTextPasswordVerifyParm == null) {
            throw new ValidationException(ValidationException.FIELD_PASSWORD_VERIFY, ValidationException.REASON_CANNOT_BE_NULL);
        }
        
        String newClearTextPassword = newClearTextPasswordParm.getClearTextPassword();
        String newClearTextPasswordVerify = newClearTextPasswordVerifyParm.getClearTextPassword();
        
        if (!newClearTextPassword.equals(newClearTextPasswordVerify)) {
            throw new ValidationException(ValidationException.FIELD_PASSWORD_VERIFY, ValidationException.REASON_PASSWORD_VERIFY_DOES_NOT_MATCH_PASSWORD);
        }
        
        Password password = new Password();
                
        // If we are in the midst of a migration, then do not perform any password policy checking.
        if (!ServiceProvider.isPerformingMigration()) {
                        
            if (minPasswordLength != -1 && newClearTextPassword.length() < minPasswordLength) {
                throw new PasswordPolicyException("Reason.57:Invalid password length: [" + newClearTextPassword.length() + "] required [" + minPasswordLength + "]", PasswordPolicyException.MIN_PASSWORD_LENGTH_NOT_MET);
            }

            if (newClearTextPassword.length() > 128) {
                throw new PasswordPolicyException("Reason.62:Password length [" + newClearTextPassword.length() + "] exceeds the maximum length of [128]" , PasswordPolicyException.MAX_PASSWORD_LENGTH_EXCEEDED);
            }
        }
        
        String encodedPassword = encodePassword(newClearTextPasswordParm);
                
        password.setEncodedPassword(encodedPassword);
        password.setCreationDate(creationDate);
        password.setIsPasswordExpired(isPasswordExpired);
        
        password.validate();
        
        return password;
    }
}