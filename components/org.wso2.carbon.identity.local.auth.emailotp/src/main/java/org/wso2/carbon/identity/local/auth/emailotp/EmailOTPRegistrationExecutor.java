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

package org.wso2.carbon.identity.local.auth.emailotp;

import org.wso2.carbon.identity.local.auth.emailotp.util.RegistrationUtils;
import org.wso2.carbon.identity.user.self.registration.action.AttributeCollection;
import org.wso2.carbon.identity.user.self.registration.action.Authentication;
import org.wso2.carbon.identity.user.self.registration.action.Verification;
import org.wso2.carbon.identity.user.self.registration.exception.RegistrationFrameworkException;
import org.wso2.carbon.identity.user.self.registration.model.ExecutorResponse;
import org.wso2.carbon.identity.user.self.registration.model.InitData;
import org.wso2.carbon.identity.user.self.registration.model.InputMetaData;
import org.wso2.carbon.identity.user.self.registration.model.RegistrationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.Claims.EMAIL_CLAIM;
import static org.wso2.carbon.identity.user.self.registration.util.Constants.STATUS_ACTION_COMPLETE;
import static org.wso2.carbon.identity.user.self.registration.util.Constants.STATUS_ATTR_REQUIRED;
import static org.wso2.carbon.identity.user.self.registration.util.Constants.STATUS_VERIFICATION_REQUIRED;

/**
 * This class handles the user registration tasks related to email OTP.
 */
public class EmailOTPRegistrationExecutor implements Authentication, AttributeCollection, Verification {

    private static final String EMAIL_OTP = "email-otp";

    public String getName() {

        return "EmailOTPVerifier";
    }

    @Override
    public ExecutorResponse authenticate(Map<String, String> input, RegistrationContext context) {

        return null;
    }

    @Override
    public ExecutorResponse collect(Map<String, String> input, RegistrationContext context) {

        // Implement the actual task logic here
        if (input != null && !input.isEmpty() && input.containsKey(EMAIL_CLAIM)) {
            // Store the email address in the context
            // Update the required data
            return new ExecutorResponse(STATUS_ACTION_COMPLETE);
        }
        ExecutorResponse executorResponse = new ExecutorResponse(STATUS_ATTR_REQUIRED);
        executorResponse.setRequiredData(getEmailMetaData());
        return executorResponse;
    }


    private List<InputMetaData> getEmailMetaData() {

        // Define a new list of InputMetaData and add the data object and return the list.
        List<InputMetaData> inputMetaData = new ArrayList<>();
        InputMetaData data = new InputMetaData(EMAIL_CLAIM, "string", 1);
        inputMetaData.add(data);
        return inputMetaData;
    }

    private List<InputMetaData> getOTPMetaData() {

        List<InputMetaData> inputMetaData = new ArrayList<>();
        InputMetaData data = new InputMetaData(EMAIL_OTP, "otp", 1);
        inputMetaData.add(data);
        return inputMetaData;
    }

    @Override
    public ExecutorResponse verify(Map<String, String> input, RegistrationContext context) {

        // Implement the actual task logic here
        if (input != null && !input.isEmpty() && input.containsKey(EMAIL_OTP)) {
            try {
                initiateEmailVerification(input, context);
            } catch (RegistrationFrameworkException e) {
                throw new RuntimeException(e);
            }
            return new ExecutorResponse(STATUS_ACTION_COMPLETE);
        }

        try {
            if (input != null) {
                RegistrationUtils.sendEmailOTP(context, "dummy-user", input.get(EMAIL_CLAIM));
            }
        } catch (RegistrationFrameworkException e) {
            throw new RuntimeException(e);
        }
        ExecutorResponse executorResponse = new ExecutorResponse(STATUS_VERIFICATION_REQUIRED);
        executorResponse.setRequiredData(getOTPMetaData());
        return executorResponse;
    }

    @Override
    public List<InitData> getInitData() {

        List<InitData> initData = new ArrayList<>();
        initData.add(getAttrCollectInitData());
        initData.add(getVerificationInitData());
        return initData;
    }

    @Override
    public InitData getAuthInitData() {

        return new InitData(STATUS_ATTR_REQUIRED, getEmailMetaData());
    }

    @Override
    public InitData getAttrCollectInitData() {

        return new InitData(STATUS_ATTR_REQUIRED, getEmailMetaData());
    }

    @Override
    public InitData getVerificationInitData() {

        return new InitData(STATUS_VERIFICATION_REQUIRED, getOTPMetaData());
    }

//    public String maskEmail(String email) {
//
//        int atIndex = email.indexOf('@');
//        if (atIndex >= 0) {
//            String masked = email.substring(0, 2)
//                    + email.substring(2, atIndex).replaceAll(".", "*")
//                    + email.substring(atIndex);
//            return masked;
//        }
//        return email;
//    }

    private void initiateEmailVerification(Map<String, String> inputs, RegistrationContext context)
            throws RegistrationFrameworkException {

        String emailOTP = inputs.get(EMAIL_OTP);
        boolean validOTP = RegistrationUtils.verifyOTP(context, emailOTP);
        if (!validOTP) {
            throw new RegistrationFrameworkException("Invalid Email OTP.");
        }
//        user.addUserStatus("emailVerified");
    }

//    public void processEmailOnboarding(Map<String, String> inputs, RegistrationRequestedUser user)
//            throws RegistrationFrameworkException {
//
//        String providedEmail = extractEmailFromRequest(inputs);
//        if (providedEmail == null) {
//            throw new RegistrationFrameworkException("Expected to set an email for the user.");
//        }
//        user.addClaim(EMAIL_CLAIM, providedEmail);
//        if (user.getUsername() == null) {
//            user.setUsername(providedEmail);
//        }
//    }

    public String extractEmailFromRequest(Map<String, String> inputs) {

        if (inputs != null) {
            return inputs.get(EMAIL_CLAIM);
        }
        return null;
    }
}
