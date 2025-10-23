/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
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

import com.duosecurity.Client;
import com.duosecurity.client.Admin;
import com.duosecurity.client.Http;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.Token;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.duo.internal.DuoServiceHolder;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Mobile based 2nd factor Federated Authenticator.
 */
public class DuoAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 4438354156955223654L;
    private static final Log log = LogFactory.getLog(DuoAuthenticator.class);
    private static final String[] NON_USER_ATTRIBUTES
            = new String[]{ "iss", "aud", "exp", "iat", "auth_time", "auth_result" };

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return request.getParameter(DuoAuthenticatorConstants.DUO_STATE) != null &&
                request.getParameter(DuoAuthenticatorConstants.DUO_CODE) != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        context.setProperty(DuoAuthenticatorConstants.AUTHENTICATION, DuoAuthenticatorConstants.AUTHENTICATOR_NAME);
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(IdentityHelperConstants.SUPER_TENANT_DOMAIN)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, context.getProperty(
                    IdentityHelperConstants.AUTHENTICATION).toString(), tenantDomain);
        }
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        Client duoClient;

        // Resolving claim needed for authentication process
        String duoUserId = getDuoUserId(context);

        if (context.isRetrying()) {
            checkStatusCode(response, context);
        } else if (StringUtils.isNotEmpty(duoUserId)) {
            try {
                String redirectUri = getCallbackUrl() + "?" +
                        FrameworkConstants.SESSION_DATA_KEY + "=" + context.getContextIdentifier();

                // Step 1: Create Duo Client
                duoClient = new Client.Builder(authenticatorProperties.get
                        (DuoAuthenticatorConstants.CLIENT_ID), authenticatorProperties.get
                        (DuoAuthenticatorConstants.CLIENT_SECRET), authenticatorProperties.get
                        (DuoAuthenticatorConstants.HOST), redirectUri).build();
                // Step 2: Call Duo health check
                duoClient.healthCheck();
                String state = duoClient.generateState();
                context.setProperty(DuoAuthenticatorConstants.DUO_STATE, state);

                // Step 3: Generate and save a state variable for validation purposes
                String duoUrl = duoClient.createAuthUrl(duoUserId, state);

                // Step 4: Create the authUrl and redirect to it
                response.sendRedirect(duoUrl);
            } catch (IOException e) {
                log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_REDIRECTING, e);
                throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_REDIRECTING, e);
            } catch (DuoException e) {
                throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_CLIENT_CREATION, e);
            } catch (URLBuilderException e) {
                throw new AuthenticationFailedException("Error occurred while building the callback URL", e);
            }
        } else {
            throw new AuthenticationFailedException("Duo authenticator failed to initialize");
        }
    }

    private String getCallbackUrl() throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build().getAbsolutePublicURL();
    }
    /**
     * Check if the tenant domain should be appended or not.
     *
     * @param authenticatorProperties the authenticator properties
     * @return True if the tenant domain should not be appended.
     */
    private boolean isDisableTenantDomainInUserName(Map<String, String> authenticatorProperties) {

        return Boolean.parseBoolean(authenticatorProperties.get(DuoAuthenticatorConstants.TENANT_DOMAIN));
    }

    /**
     * Check if the user store domain should be appended or not.
     *
     * @param authenticatorProperties the authenticator properties
     * @return True if the user store domain should not be appended.
     */
    private boolean isDisableUserStoreDomainInUserName(Map<String, String> authenticatorProperties) {

        return Boolean.parseBoolean(authenticatorProperties.get(DuoAuthenticatorConstants.USER_STORE_DOMAIN));
    }

    /**
     * Check if the username is used as the identifier.
     *
     * @return True if the config is enabled.
     */
    private boolean isUsernameAsDuoIdentifier() {

        Map<String, String> duoParameters = getAuthenticatorConfig().getParameterMap();
        return Boolean.parseBoolean(duoParameters.get(DuoAuthenticatorConstants.USERNAME_AS_DUO_IDENTIFIER));
    }

    /**
     * Get Duo user's information.
     *
     * @param context  the authentication context
     * @param duoUserId the username
     * @return Duo user information
     * @throws AuthenticationFailedException
     */
    private JSONArray getUserInfo(AuthenticationContext context, String duoUserId)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        Http duoAdminRequest = new Admin.AdminBuilder(DuoAuthenticatorConstants.HTTP_GET,
                        authenticatorProperties.get(DuoAuthenticatorConstants.HOST),
                        DuoAuthenticatorConstants.API_USER).build();
        duoAdminRequest.addParam(DuoAuthenticatorConstants.DUO_USERNAME, duoUserId);
        try {
            duoAdminRequest.signRequest(authenticatorProperties.get(DuoAuthenticatorConstants.ADMIN_IKEY),
                    authenticatorProperties.get(DuoAuthenticatorConstants.ADMIN_SKEY));
            //Execute Duo API request
            Object result = duoAdminRequest.executeRequest();
            JSONArray userInfo = new JSONArray(result.toString());
            if (userInfo.length() == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Couldn't get the Duo user information");
                }
                context.setProperty(DuoAuthenticatorConstants.USER_NOT_REGISTERED_IN_DUO, true);
                throw new AuthenticationFailedException("Couldn't find the user information ");
            }
            return userInfo;
        } catch (UnsupportedEncodingException e) {
            log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_SIGN_REQUEST, e);
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_SIGN_REQUEST, e);
        } catch (JSONException e) {
            log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_JSON, e);
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_JSON, e);
        } catch (Exception e) {
            log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_EXECUTE_REQUEST, e);
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_EXECUTE_REQUEST, e);
        }
    }

    /**
     * Check the validation of phone numbers.
     *
     * @param context  the authentication context
     * @param username the user name
     * @throws AuthenticationFailedException
     * @throws JSONException
     */
    private void checkPhoneNumberValidation(AuthenticationContext context, String username, String duoUserId)
            throws AuthenticationFailedException, JSONException {

        String mobile = getMobileClaimValue(context);
        if (StringUtils.isNotEmpty(mobile)) {
            JSONArray userInfo = getUserInfo(context, duoUserId);
            context.setProperty(DuoAuthenticatorConstants.USER_INFO, userInfo);
            JSONObject object = userInfo.getJSONObject(0);
            JSONArray phoneArray = (JSONArray) object.get(DuoAuthenticatorConstants.DUO_PHONES);
            if (isValidPhoneNumber(context, phoneArray, mobile)) {
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("The mobile claim value and registered Duo mobile number should be in same format");
                }
                context.setProperty(DuoAuthenticatorConstants.NUMBER_MISMATCH, true);
                throw new AuthenticationFailedException("Authentication failed due to mismatch in mobile numbers");
            }
        } else {
            context.setProperty(DuoAuthenticatorConstants.MOBILE_CLAIM_NOT_FOUND, true);
            throw new AuthenticationFailedException("Error while getting the mobile number from user's profile " +
                    "for username " + username);
        }
    }

    /**
     * Verify the duo phone number with user's mobile claim value.
     *
     * @param context    the authentication context
     * @param phoneArray array with phone numbers
     * @param mobile     the mobile claim value
     * @return true or false
     * @throws AuthenticationFailedException
     * @throws JSONException
     */
    private boolean isValidPhoneNumber(AuthenticationContext context, JSONArray phoneArray, String mobile)
            throws AuthenticationFailedException, JSONException {

        if (phoneArray.length() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Couldn't get the phone number of Duo user");
            }
            context.setProperty(DuoAuthenticatorConstants.MOBILE_NUMBER_NOT_FOUND, true);
            throw new AuthenticationFailedException("User doesn't have a mobile number in Duo for Authentication ");
        } else {
            for (int i = 0; i < phoneArray.length(); i++) {
                if (((JSONObject) phoneArray.get(i)).getString(DuoAuthenticatorConstants.DUO_NUMBER).equals(mobile)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check the status codes when retry enabled.
     *
     * @param response the HttpServletResponse
     * @param context  the AuthenticationContext
     * @throws AuthenticationFailedException
     */
    private void checkStatusCode(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String redirectUrl = getErrorPage(context);
        try {
            if (Boolean.parseBoolean(String.valueOf(context.getProperty(DuoAuthenticatorConstants.NUMBER_MISMATCH)))) {
                response.sendRedirect(redirectUrl + DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_MISMATCH);
            } else if (Boolean.parseBoolean(String.valueOf(context.getProperty
                    (DuoAuthenticatorConstants.USER_NOT_REGISTERED_IN_DUO)))) {
                response.sendRedirect(redirectUrl + DuoAuthenticatorConstants.DuoErrors.ERROR_USER_NOT_REGISTERED);
            } else if (Boolean.parseBoolean(String.valueOf(context.getProperty
                    (DuoAuthenticatorConstants.MOBILE_NUMBER_NOT_FOUND)))) {
                response.sendRedirect(redirectUrl + DuoAuthenticatorConstants.DuoErrors.ERROR_GETTING_NUMBER_FROM_DUO);
            } else if (Boolean.parseBoolean(String.valueOf(context.getProperty
                    (DuoAuthenticatorConstants.MOBILE_CLAIM_NOT_FOUND)))) {
                response.sendRedirect(redirectUrl + DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_NOT_FOUND);
            } else if (Boolean.parseBoolean(String.valueOf(context.getProperty
                    (DuoAuthenticatorConstants.UNABLE_TO_FIND_VERIFIED_USER)))) {
                response.sendRedirect(redirectUrl + DuoAuthenticatorConstants.DuoErrors.ERROR_GETTING_VERIFIED_USER);
            }
        } catch (IOException e) {
            String msg = "Authentication Failed: An IOException was caught.";
            log.error(msg, e);
            throw new AuthenticationFailedException(msg, e);
        }
    }

    /**
     * Get Duo custom error page to handle exception.
     *
     * @param context authentication
     * @return redirect url
     */
    private String getErrorPage(AuthenticationContext context) {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        Map<String, String> duoParameters = getAuthenticatorConfig().getParameterMap();
        String duoErrorPageEndpoint = duoParameters.get(
                DuoAuthenticatorConstants.DUO_AUTHENTICATION_ENDPOINT_ERROR_PAGE);
        if (duoErrorPageEndpoint == null) {
            duoErrorPageEndpoint = DuoAuthenticatorConstants.DUO_DEFAULT_ERROR_PAGE;
        }
        String duoErrorPageUrl = duoErrorPageEndpoint + "?" + queryParams + "&" +
                DuoAuthenticatorConstants.AUTHENTICATION + "=" + getName();
        return IdentityUtil.getServerURL(duoErrorPageUrl, false, false);
    }

    /**
     * Get the mobile claim value of user based on application.authentication.xml configuration.
     *
     * @param authenticationContext the Authentication Context
     * @return the mobile claim value
     * @throws AuthenticationFailedException
     */
    private String getMobileClaimValue(AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        String mobileNumber;
        String username;
        String federatedMobileNumberAttributeKey;
        AuthenticatedUser authenticatedUser;
        Map<ClaimMapping, String> userAttributes;
        Map<String, String> duoParameters;

        authenticatedUser = (AuthenticatedUser) authenticationContext
                .getProperty(DuoAuthenticatorConstants.AUTHENTICATED_USER);

        if (authenticatedUser == null) {
            if (log.isDebugEnabled()) {
                log.debug("Authentication failed: Could not find the authenticated user. ");
            }
            throw new AuthenticationFailedException
                    ("Authentication failed: Cannot proceed further without identifying the user. ");
        }
        username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        duoParameters = FederatedAuthenticatorUtil.getAuthenticatorConfig(DuoAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (duoParameters != null
                && duoParameters.get(DuoAuthenticatorConstants.SEND_DUO_TO_FEDERATED_MOBILE_ATTRIBUTE) != null
                && Boolean.parseBoolean(
                duoParameters.get(DuoAuthenticatorConstants.SEND_DUO_TO_FEDERATED_MOBILE_ATTRIBUTE))) {

            userAttributes = authenticatedUser.getUserAttributes();
            federatedMobileNumberAttributeKey = duoParameters
                    .get(DuoAuthenticatorConstants.FEDERATED_MOBILE_ATTRIBUTE_KEY);

            if (federatedMobileNumberAttributeKey == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication failed: 'federatedMobileNumberAttributeKey' property is undefined");
                }
                throw new AuthenticationFailedException
                        ("Authentication failed: 'federatedMobileNumberAttributeKey' property is undefined");
            }
            mobileNumber = getMobileNumberForFederatedUser(userAttributes, federatedMobileNumberAttributeKey);
        } else {
            try {
                int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                UserRealm userRealm = DuoServiceHolder.getInstance().getRealmService().getTenantUserRealm(tenantId);
                String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                if (userRealm != null) {
                    UserStoreManager userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                    mobileNumber = userStoreManager.getUserClaimValue(tenantAwareUsername,
                            DuoAuthenticatorConstants.MOBILE_CLAIM, null);
                } else {
                    throw new AuthenticationFailedException(
                            "Cannot find the user realm for the given tenant: " + tenantId);
                }
            } catch (UserStoreException e) {
                log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_USER_STORE, e);
                throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_USER_STORE, e);
            }
        }

        return mobileNumber;
    }

    /**
     * Extract the mobile number value from federated user attributes.
     *
     * @param userAttributes                    {@link Map} with federated user attributes
     * @param federatedMobileNumberAttributeKey used to identify the mobile number value of federated authenticator
     * @return the mobile number attribute
     */
    private String getMobileNumberForFederatedUser(Map<ClaimMapping, String> userAttributes,
                                                   String federatedMobileNumberAttributeKey) {

        String mobileNumber = null;
        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
            String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
            String value = entry.getValue();
            if (key.equals(federatedMobileNumberAttributeKey)) {
                mobileNumber = String.valueOf(value);
                break;
            }
        }
        return mobileNumber;
    }

    /**
     * Extract the mobile number value from federated user attributes.
     *
     * @param contextState  state value of the authentication context
     * @param responseState state value of the duo response
     */
    private boolean isValidResponse(String contextState, String responseState) {

        if (contextState != null && contextState.equals(responseState)) {

            if (log.isDebugEnabled()) {
                log.debug("Duo response state matches with the context state");
            }
            return true;
        } else {
            return false;
        }
    }

    /**
     * Extract the mobile number value from federated user attributes.
     *
     * @param context         the AuthenticationContext
     */
    private String getDuoUserId(AuthenticationContext context) throws AuthenticationFailedException {

        if (log.isDebugEnabled()) {
            log.debug("Read the Claim value which will be passed to duo.");
        }
        Map<String, String> runtimeParams = getRuntimeParams(context);

        if (runtimeParams != null) {
            String duoUserId = runtimeParams.get(DuoAuthenticatorConstants.DUO_USER_IDENTIFIER);
            if (StringUtils.isNotBlank(duoUserId)) {
                if (log.isDebugEnabled()) {
                    log.debug("The claim obtained from the runtime parameters was passed to Duo.");
                }
                return duoUserId;
            }
        }
        if (isUsernameAsDuoIdentifier()) {
            return getUsername(context);
        }
        return getUserId(context);
    }

    /**
     * Extract the username of the authenticating user.
     *
     * @param context         {@link AuthenticationContext}
     */
    private String getUsername(AuthenticationContext context) throws AuthenticationFailedException {

        String username = String.valueOf(context.getProperty(DuoAuthenticatorConstants.DUO_USERNAME));
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context
                .getProperty(DuoAuthenticatorConstants.AUTHENTICATED_USER);

        if (authenticatedUser != null) {
            username = authenticatedUser.getUserName();
        }

        if (username == null) {
            throw new AuthenticationFailedException("Authentication failed!. Cannot proceed further without " +
                    "identifying the user");
        }
        if (!isDisableTenantDomainInUserName(authenticatorProperties)) {
            username = UserCoreUtil.addTenantDomainToEntry(username, authenticatedUser.getTenantDomain());
        }
        if (!isDisableUserStoreDomainInUserName(authenticatorProperties)) {
            username = IdentityUtil.addDomainToName(username, authenticatedUser.getUserStoreDomain());
        }

        return username;
    }

    /**
     * Extract the user ID of the authenticating user.
     *
     * @param context         {@link AuthenticationContext}
     */
    private String getUserId(AuthenticationContext context) throws AuthenticationFailedException {

        String userId = null;
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context
                .getProperty(DuoAuthenticatorConstants.AUTHENTICATED_USER);

        try {
            if (authenticatedUser != null) {
                userId = authenticatedUser.getUserId();
            }
            if (userId == null) {
                throw new UserIdNotFoundException("User id not found for the authenticated user");
            }
        } catch (UserIdNotFoundException e) {
            throw new AuthenticationFailedException("Authentication failed!. Cannot proceed further without " +
                    "identifying the user");
        }
        return userId;
    }

    /**
     * Get the configuration properties of UI.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property duoHost = new Property();
        duoHost.setDisplayName("API hostname");
        duoHost.setName(DuoAuthenticatorConstants.HOST);
        duoHost.setDescription("Enter host name of Duo Account");
        duoHost.setRequired(true);
        duoHost.setDisplayOrder(1);
        configProperties.add(duoHost);

        Property integrationKey = new Property();
        integrationKey.setDisplayName("Client ID");
        integrationKey.setName(DuoAuthenticatorConstants.CLIENT_ID);
        integrationKey.setDescription("Enter Client ID");
        integrationKey.setRequired(true);
        integrationKey.setDisplayOrder(2);
        configProperties.add(integrationKey);

        Property secretKey = new Property();
        secretKey.setDisplayName("Client Secret");
        secretKey.setName(DuoAuthenticatorConstants.CLIENT_SECRET);
        secretKey.setDescription("Enter Client Secret");
        secretKey.setRequired(true);
        secretKey.setConfidential(true);
        secretKey.setDisplayOrder(3);
        configProperties.add(secretKey);

        Property adminIntegrationKey = new Property();
        adminIntegrationKey.setDisplayName("Admin Integration Key");
        adminIntegrationKey.setName(DuoAuthenticatorConstants.ADMIN_IKEY);
        adminIntegrationKey.setDescription("Enter Admin Integration Key (Necessary for mobile number verification)");
        adminIntegrationKey.setRequired(false);
        adminIntegrationKey.setDisplayOrder(4);
        configProperties.add(adminIntegrationKey);

        Property adminSecretKey = new Property();
        adminSecretKey.setName(DuoAuthenticatorConstants.ADMIN_SKEY);
        adminSecretKey.setDisplayName("Admin Secret Key");
        adminSecretKey.setRequired(false);
        adminSecretKey.setDescription("Enter Admin Secret Key (Necessary for mobile number verification)");
        adminSecretKey.setConfidential(true);
        adminSecretKey.setDisplayOrder(5);
        configProperties.add(adminSecretKey);

        Property disableUserStoreDomain = new Property();
        disableUserStoreDomain.setName(DuoAuthenticatorConstants.USER_STORE_DOMAIN);
        disableUserStoreDomain.setDisplayName("Disable User Store Domain");
        disableUserStoreDomain.setRequired(false);
        disableUserStoreDomain.setDescription("Configure as true to disable user store domain");
        disableUserStoreDomain.setValue("true");
        disableUserStoreDomain.setDisplayOrder(6);
        disableUserStoreDomain.setType("boolean");
        configProperties.add(disableUserStoreDomain);

        Property disableTenantDomain = new Property();
        disableTenantDomain.setName(DuoAuthenticatorConstants.TENANT_DOMAIN);
        disableTenantDomain.setDisplayName("Disable Tenant Domain");
        disableTenantDomain.setRequired(false);
        disableTenantDomain.setDescription("Configure as true to disable tenant domain");
        disableTenantDomain.setValue("true");
        disableTenantDomain.setDisplayOrder(7);
        disableTenantDomain.setType("boolean");
        configProperties.add(disableTenantDomain);

        return configProperties;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, String> duoParameters = getAuthenticatorConfig().getParameterMap();
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String requestState = request.getParameter(DuoAuthenticatorConstants.DUO_STATE);
        String requestDuoCode = request.getParameter(DuoAuthenticatorConstants.DUO_CODE);
        Client duoClient;
        String username;

        try {
            // Step 5: Validate state returned from Duo is the same as the one saved previously.
            // If it isn't return an error
            boolean isValidResponse = isValidResponse(context.getProperty(DuoAuthenticatorConstants.DUO_STATE).
                    toString(), requestState);

            if (!isValidResponse) {
                throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER,
                        "Authentication failed!. Duo response state does not match with the context state");
            }
            AuthenticatedUser authenticatedUser = (AuthenticatedUser) context
                    .getProperty(DuoAuthenticatorConstants.AUTHENTICATED_USER);
            if (authenticatedUser == null) {
                throw new AuthenticationFailedException("Authentication failed!. Cannot proceed further without " +
                        "identifying the user");
            }

            username = authenticatedUser.getAuthenticatedSubjectIdentifier();

            if (username == null) {
                throw new AuthenticationFailedException("Authentication failed!. Cannot proceed further without " +
                        "identifying the user");
            }

            String redirectUri = getCallbackUrl() + "?" +
                    FrameworkConstants.SESSION_DATA_KEY + "=" + getContextIdentifier(request);

            duoClient = new Client.Builder(authenticatorProperties.get
                    (DuoAuthenticatorConstants.CLIENT_ID), authenticatorProperties.get
                    (DuoAuthenticatorConstants.CLIENT_SECRET), authenticatorProperties.get
                    (DuoAuthenticatorConstants.HOST), redirectUri).build();
        } catch (DuoException e) {
            log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_CLIENT_CREATION, e);
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_CLIENT_CREATION, e);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error occurred while building the callback URL", e);
        }

        try {
            // Step 6: Exchange the auth duoCode for a Token object which contains metadata about authentication.
            String duoUserId = getDuoUserId(context);
            Token duoToken = duoClient.exchangeAuthorizationCodeFor2FAResult(requestDuoCode, duoUserId);

            if (log.isDebugEnabled()) {
                log.debug("Duo Authentication status: " + duoToken.getAuth_result().getStatus_msg());
            }
            if (StringUtils.isNotEmpty(username)) {
                if (Boolean.parseBoolean(duoParameters.get(DuoAuthenticatorConstants.ENABLE_MOBILE_VERIFICATION))) {
                    checkPhoneNumberValidation(context, username, duoUserId);
                }
                AuthenticatedUser authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(duoUserId);
                authenticatedUser.setUserAttributes(getUserAttributesFromDuoToken(duoToken));
                context.setSubject(authenticatedUser);
            } else {
                context.setProperty(DuoAuthenticatorConstants.UNABLE_TO_FIND_VERIFIED_USER, true);
                throw new AuthenticationFailedException("Unable to find verified user from Duo");
            }
        } catch (DuoException e) {
            log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_TOKEN_CREATION, e);
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_TOKEN_CREATION, e);
        } catch (JSONException e) {
            log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_USER_ATTRIBUTES, e);
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_USER_ATTRIBUTES, e);
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(DuoAuthenticatorConstants.SESSION_DATA_KEY);
    }

    @Override
    public String getName() {

        return DuoAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return DuoAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    private Map<ClaimMapping, String> getUserAttributesFromDuoToken(Token duoToken) {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        ObjectMapper objectMapper = new ObjectMapper();
        TypeReference<Map<String, Object>> reference = new TokenTypeReference();
        Map<String, Object> map = objectMapper.convertValue(duoToken, reference);

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (Arrays.stream(NON_USER_ATTRIBUTES).noneMatch(entry.getKey()::equals)) {
                if (entry.getKey().equals(DuoAuthenticatorConstants.AUTH_CONTEXT) && entry.getValue() instanceof Map) {
                    Map<String, Object> authContext = (Map<String, Object>) entry.getValue();
                    // Add amr value
                    if (authContext.get(DuoAuthenticatorConstants.FACTOR) != null) {
                        userAttributes.put(
                                ClaimMapping.build(DuoAuthenticatorConstants.AMR, DuoAuthenticatorConstants.AMR,
                                        null, false),
                                authContext.get(DuoAuthenticatorConstants.FACTOR).toString());
                    } else {
                        log.debug("Skipping addition of AMR attribute due to factor value being null.");
                    }
                } else if (entry.getValue() instanceof String) {
                    userAttributes.put(
                            ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                            entry.getValue().toString());
                }
            }
        }
        return userAttributes;
    }

    private static final class TokenTypeReference extends TypeReference<Map<String, Object>> { }
}
