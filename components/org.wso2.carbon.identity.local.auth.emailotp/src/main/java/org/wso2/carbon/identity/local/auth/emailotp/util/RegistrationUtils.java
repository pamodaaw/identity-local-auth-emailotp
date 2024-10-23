/*
 *  Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.local.auth.emailotp.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.exception.EmailOtpAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.user.self.registration.exception.RegistrationFrameworkException;
import org.wso2.carbon.identity.user.self.registration.model.RegistrationContext;

import java.security.SecureRandom;
import java.util.HashMap;

import static org.wso2.carbon.identity.event.handler.notification.NotificationConstants.EmailNotification.ARBITRARY_SEND_TO;
import static org.wso2.carbon.identity.event.handler.notification.NotificationConstants.EmailNotification.EMAIL_TEMPLATE_TYPE;

/**
 * Utility class for registration related operations.
 */
public class RegistrationUtils {

    private static final Log LOG = LogFactory.getLog(RegistrationUtils.class);

    public static void sendEmailOTP(RegistrationContext context, String username, String email)
            throws RegistrationFrameworkException {

        context.setTenantDomain("carbon.super");
        String myToken = generateOTP(context.getTenantDomain());

        context.setProperty(AuthenticatorConstants.OTP_TOKEN, myToken);
        context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());

        triggerEmail(username, email, myToken, context.getTenantDomain());
    }

    private static void triggerEmail(String username, String emailAddress, String emailOTP,
                                     String tenantDomain) throws RegistrationFrameworkException {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, username);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, "PRIMARY");
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put(AuthenticatorConstants.CODE, emailOTP);
        properties.put(EMAIL_TEMPLATE_TYPE, AuthenticatorConstants.EMAIL_OTP_TEMPLATE_NAME);
        properties.put(ARBITRARY_SEND_TO, emailAddress);

        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AuthenticatorDataHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "An error occurred while triggering the event. " + e.getMessage();
            throw new RegistrationFrameworkException(errorMsg);
        }
    }

    private static String generateOTP(String tenantDomain) throws RegistrationFrameworkException {

        String charSet = getOTPCharset(tenantDomain);
        int otpLength = getOTPLength(tenantDomain);

        char[] chars = charSet.toCharArray();
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            sb.append(chars[rnd.nextInt(chars.length)]);
        }
        return sb.toString();
    }

    private static String getOTPCharset(String tenantDomain) throws RegistrationFrameworkException {

        try {
            boolean useAlphanumericChars = Boolean.parseBoolean(
                    AuthenticatorUtils.getEmailAuthenticatorConfig(
                            AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_ALPHANUMERIC_CHARS, tenantDomain));
            if (useAlphanumericChars) {
                return AuthenticatorConstants.EMAIL_OTP_UPPER_CASE_ALPHABET_CHAR_SET +
                        AuthenticatorConstants.EMAIL_OTP_NUMERIC_CHAR_SET;
            }
            return AuthenticatorConstants.EMAIL_OTP_NUMERIC_CHAR_SET;
        } catch (EmailOtpAuthenticatorServerException exception) {
            throw new RegistrationFrameworkException("Error while reading authenticator configurations.");
        }
    }

    private static long getOtpValidityPeriod(String tenantDomain) throws RegistrationFrameworkException {

        try {
            String value = AuthenticatorUtils.getEmailAuthenticatorConfig(
                    AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME, tenantDomain);
            if (StringUtils.isBlank(value)) {
                return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
            }
            long validityTime;
            try {
                validityTime = Long.parseLong(value);
            } catch (NumberFormatException e) {
                LOG.error(String.format("Email OTP validity period value: %s configured in tenant : %s is not a " +
                                                "number. Therefore, default validity period: %s (milli-seconds) will " +
                                                "be used",
                                        value, tenantDomain,
                                        AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS));
                return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
            }
            // We don't need to send tokens with infinite validity.
            if (validityTime < 0) {
                LOG.error(String.format("Email OTP validity period value: %s configured in tenant : %s cannot be a " +
                                                "negative number. Therefore, default validity period: %s " +
                                                "(milli-seconds) will be used", value, tenantDomain,
                                        AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS));
                return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
            }
            // Converting to milliseconds since the config is provided in seconds.
            return validityTime * 1000;
        } catch (EmailOtpAuthenticatorServerException exception) {
            throw new RegistrationFrameworkException("Error while reading authenticator configurations.");
        }
    }

    private static int getOTPLength(String tenantDomain) throws RegistrationFrameworkException {

        try {
            int otpLength = AuthenticatorConstants.DEFAULT_OTP_LENGTH;
            String configuredOTPLength = AuthenticatorUtils.getEmailAuthenticatorConfig(
                    AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH, tenantDomain);
            if (NumberUtils.isNumber(configuredOTPLength)) {
                otpLength = Integer.parseInt(configuredOTPLength);
            }
            return otpLength;
        } catch (EmailOtpAuthenticatorServerException exception) {
            throw new RegistrationFrameworkException("Error while reading authenticator configurations.");
        }
    }

    public static boolean verifyOTP(RegistrationContext context, String otp) throws RegistrationFrameworkException {

        String contextToken = (String) context.getProperty(AuthenticatorConstants.OTP_TOKEN);
        boolean isExpired = isOtpExpired(context.getTenantDomain(), context);

        return contextToken.equals(otp) && !isExpired;
    }

    private static boolean isOtpExpired(String tenantDomain, RegistrationContext context)
            throws RegistrationFrameworkException {

        if (context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME) == null) {
            throw new RegistrationFrameworkException("OTP generated time is not set in the context.");
        }
        long generatedTime = (long) context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME);
        long expireTime = getOtpValidityPeriod(tenantDomain);
        return System.currentTimeMillis() >= generatedTime + expireTime;
    }
}
