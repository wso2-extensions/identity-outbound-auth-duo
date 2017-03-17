/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.duo;

import java.util.Random;

/**
 * Constants used by the DuoAuthenticator
 */
public abstract class DuoAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "DuoAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "duo";
    public static final String INTEGRATION_KEY = "IntegrationKey";
    public static final String SECRET_KEY = "SecretKey";
    public static final String ADMIN_IKEY = "AdminIntegrationKey";
    public static final String ADMIN_SKEY = "AdminSecretKey";
    public static final String HOST = "DuoHost";
    public static final String SIG_RESPONSE = "sig_response";
    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    public static final String DUO_NUMBER = "number";
    public static final String API_USER = "/admin/v1/users";
    public static final String DUO_USERNAME = "username";
    public static final String DEFAULT_USER_IDENTIFIER = "username";
    public static final String DUO_PHONES = "phones";
    public static final String DUO_PAGE = "duoauthenticationendpoint/duoAuth.jsp";
    public static final String ENABLE_MOBILE_VERIFICATION = "EnableMobileVerification";
    public static final String OVERRIDE_USERNAME_CLAIM = "OverrideUsernameClaim";
    public static final String INTEGRATION_SECRET_KEY = "integrationSecretKey";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String HTTP_GET = "GET";
    public static final String RAND = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static class RequestParams {
        public static final String DUO = "duo";
        public static final String SIG_REQUEST = "signreq";
        public static final String DUO_HOST = "duoHost";
    }

    public static class DuoErrors {
        public static final String ERROR_VERIFY_USER = "Error while verifying Duo user";
        public static final String ERROR_USER_STORE = "Error while getting mobile number from user store";
        public static final String ERROR_SIGN_REQUEST = "Error while signing Duo request";
        public static final String ERROR_EXECUTE_REQUEST = "Error while executing Duo API request";
        public static final String ERROR_USER_NOT_FOUND = "User is not registered in Duo. Authentication failed";
        public static final String ERROR_GETTING_PHONE = "Error getting phone in Duo. Authentication failed";
        public static final String ERROR_NUMBER_INVALID = "User doesn't have a valid mobile number for Duo Authentication";
        public static final String ERROR_NUMBER_NOT_FOUND = "User doesn't have a mobile number for Duo Authentication";
        public static final String ERROR_REDIRECTING = "Error while redirecting to Duo authentication page";
        public static final String ERROR_JSON = "Error while handling JSON object";
        public static final String ERROR_NUMBER_MISMATCH = "Authentication failed due to mismatch in mobile numbers";
    }

    /**
     * Generate integrationSecretKey for Duo Authentication
     */
    public static String stringGenerator() {
        StringBuilder sb = new StringBuilder(42);
        Random rnd = new Random();
        for (int i = 0; i < 42; i++) {
            sb.append(RAND.charAt(rnd.nextInt(DuoAuthenticatorConstants.RAND.length())));
        }
        return sb.toString();
    }
}