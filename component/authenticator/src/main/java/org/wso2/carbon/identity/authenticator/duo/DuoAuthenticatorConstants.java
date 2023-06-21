/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.duo;

/**
 * Constants used by the DuoAuthenticator.
 */
public abstract class DuoAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "DuoAuthenticator";
    public static final String AUTHENTICATION = "authentication";
    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "duo";
    public static final String CLIENT_ID = "ClientID";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String ADMIN_IKEY = "AdminIntegrationKey";
    public static final String ADMIN_SKEY = "AdminSecretKey";
    public static final String HOST = "DuoHost";
    public static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    public static final String DUO_NUMBER = "number";
    public static final String API_USER = "/admin/v1/users";
    public static final String DUO_USERNAME = "username";
    public static final String DUO_STATE = "state";
    public static final String DUO_CODE = "duo_code";
    public static final String DUO_PHONES = "phones";
    public static final String DUO_ERROR_PAGE = "authenticationendpoint/duo_error.do";
    public static final String ENABLE_MOBILE_VERIFICATION = "EnableMobileVerification";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String HTTP_GET = "GET";
    public static final String USER_NOT_REGISTERED_IN_DUO = "userNotFound";
    public static final String NUMBER_MISMATCH = "numberMismatch";
    public static final String MOBILE_NUMBER_NOT_FOUND = "unableToFindMobileNumber";
    public static final String MOBILE_CLAIM_NOT_FOUND = "unableToFindMobileClaim";
    public static final String UNABLE_TO_FIND_VERIFIED_USER = "unableToFindVerifiedUser";
    public static final String USER_INFO = "userInfo";
    public static final String USER_STORE_DOMAIN = "UserStoreDomain";
    public static final String TENANT_DOMAIN = "TenantDomain";
    public static final String SEND_DUO_TO_FEDERATED_MOBILE_ATTRIBUTE = "sendDuoToFederatedMobileAttribute";
    public static final String FEDERATED_MOBILE_ATTRIBUTE_KEY = "federatedMobileNumberAttributeKey";
    public static final String DUO_USER_IDENTIFIER = "duoUserIdentifier";

    /**
     * Duo errors.
     */
    public static class DuoErrors {
        public static final String ERROR_USER_NOT_REGISTERED = "&authFailure=true&authFailureMsg=user.not.registered";
        public static final String ERROR_GETTING_VERIFIED_USER = "&authFailure=true&authFailureMsg=user.not.found";
        public static final String ERROR_GETTING_NUMBER_FROM_DUO = "&authFailure=true&authFailureMsg=unable.to.get" +
                ".duo.mobileNumber";
        public static final String ERROR_NUMBER_NOT_FOUND = "&authFailure=true&authFailureMsg=unable.to.find.number";
        public static final String ERROR_NUMBER_MISMATCH = "&authFailure=true&authFailureMsg=number.mismatch";

        public static final String ERROR_JSON = "Error while handling JSON object";
        public static final String ERROR_USER_ATTRIBUTES = "Error while getting user attributes from Duo";
        public static final String ERROR_VERIFY_USER = "Error while verifying Duo user";
        public static final String ERROR_USER_STORE = "Error while getting mobile number from user store";
        public static final String ERROR_SIGN_REQUEST = "Error while signing Duo request";
        public static final String ERROR_EXECUTE_REQUEST = "Error while executing Duo API request";
        public static final String ERROR_REDIRECTING = "Error while redirecting to Duo authentication page";
        public static final String ERROR_CLIENT_CREATION = "Error while initiating Duo client";
        public static final String ERROR_TOKEN_CREATION = "Error while creating exchange token after 2FA";
    }
}
