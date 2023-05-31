/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.duo;

import com.duosecurity.Client;
import com.duosecurity.client.Admin;
import com.duosecurity.client.Http;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.Token;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
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
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Mobile based 2nd factor Local Authenticator.
 */
public class DuoAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 4438354156955223654L;
    private static final Log log = LogFactory.getLog(DuoAuthenticator.class);
    private transient Client duoClient;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return request.getParameter(DuoAuthenticatorConstants.AUTHENTICATOR_NAME) != null &&
                request.getParameter(DuoAuthenticatorConstants.DUO_STATE) != null &&
                request.getParameter(DuoAuthenticatorConstants.DUO_CODE) != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        context.setProperty(DuoAuthenticatorConstants.AUTHENTICATION, DuoAuthenticatorConstants.AUTHENTICATOR_NAME);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);

        // Resolving username needed for authentication process
        String username = String.valueOf(context.getProperty(DuoAuthenticatorConstants.DUO_USERNAME));
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(
                DuoAuthenticatorConstants.AUTHENTICATED_USER);

        if (authenticatedUser != null) {
            username = authenticatedUser.getUserName();
            if (!isDisableTenantDomainInUserName(authenticatorProperties)) {
                username = UserCoreUtil.addTenantDomainToEntry(username, authenticatedUser.getTenantDomain());
            }
            if (!isDisableUserStoreDomainInUserName(authenticatorProperties)) {
                username = IdentityUtil.addDomainToName(username, authenticatedUser.getUserStoreDomain());
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("user name : " + username);
        }
        if (context.isRetrying()) {
            checkStatusCode(response, context);
        } else if (StringUtils.isNotEmpty(username)) {
            try {
                String redirectUri = getCallbackUrl() + "?" +
                        FrameworkConstants.SESSION_DATA_KEY + "=" + getContextIdentifier(request) + "&" +
                        "&" + DuoAuthenticatorConstants.AUTHENTICATOR_NAME + "=true";

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
                String duoUrl = duoClient.createAuthUrl(username, state);

                // Step 4: Create the authUrl and redirect to it
                response.sendRedirect(duoUrl);
            } catch (IOException e) {
                log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_REDIRECTING, e);
                throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_REDIRECTING, e);
            } catch (DuoException e) {
                throw new AuthenticationFailedException("Error occurred while initiating Duo client", e);
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
     * Get Duo user's information.
     *
     * @param context  the authentication context
     * @param username the username
     * @return Duo user information
     * @throws AuthenticationFailedException
     */
    private JSONArray getUserInfo(AuthenticationContext context, String username) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        Http duoAdminRequest = new Admin.AdminBuilder(DuoAuthenticatorConstants.HTTP_GET,
                        authenticatorProperties.get(DuoAuthenticatorConstants.HOST),
                        DuoAuthenticatorConstants.API_USER).build();
        duoAdminRequest.addParam(DuoAuthenticatorConstants.DUO_USERNAME, username);
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
    private void checkPhoneNumberValidation(AuthenticationContext context, String username)
            throws AuthenticationFailedException, JSONException {

        String mobile = getMobileClaimValue(context);
        if (StringUtils.isNotEmpty(mobile)) {
            JSONArray userInfo = getUserInfo(context, username);
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
        String duoErrorPageUrl = DuoAuthenticatorConstants.DUO_ERROR_PAGE + "?" + queryParams + "&" +
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
        username = authenticatedUser.getUserName();
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

        if (log.isDebugEnabled()) {
            log.debug("mobile number : " + mobileNumber);
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

    private void verifyResponse(String contextState, String responseState) throws DuoException {
        if (contextState != null && responseState != null && contextState.equals(responseState)) {

            if (log.isDebugEnabled()) {
                log.debug("Duo response state matches with the context state");
            }
            return;
        } else {
            throw new DuoException("Duo response state does not match with the context state");
        }
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

        Property adminIntegrationKey = new Property();
        adminIntegrationKey.setDisplayName("Admin Integration Key");
        adminIntegrationKey.setName(DuoAuthenticatorConstants.ADMIN_IKEY);
        adminIntegrationKey.setDescription("Enter Admin Integration Key");
        adminIntegrationKey.setRequired(false);
        adminIntegrationKey.setDisplayOrder(3);
        configProperties.add(adminIntegrationKey);

        Property secretKey = new Property();
        secretKey.setDisplayName("Client Secret");
        secretKey.setName(DuoAuthenticatorConstants.CLIENT_SECRET);
        secretKey.setDescription("Enter Client Secret");
        secretKey.setRequired(true);
        secretKey.setConfidential(true);
        secretKey.setDisplayOrder(4);
        configProperties.add(secretKey);

        Property adminSecretKey = new Property();
        adminSecretKey.setName(DuoAuthenticatorConstants.ADMIN_SKEY);
        adminSecretKey.setDisplayName("Admin Secret Key");
        adminSecretKey.setRequired(false);
        adminSecretKey.setDescription("Enter Admin Secret Key");
        adminSecretKey.setConfidential(true);
        adminSecretKey.setDisplayOrder(5);
        configProperties.add(adminSecretKey);

        Property disableUserStoreDomain = new Property();
        disableUserStoreDomain.setName(DuoAuthenticatorConstants.USER_STORE_DOMAIN);
        disableUserStoreDomain.setDisplayName("Disable User Store Domain");
        disableUserStoreDomain.setRequired(false);
        disableUserStoreDomain.setDescription("Configured as true to disable user store domain");
        disableUserStoreDomain.setDisplayOrder(6);
        configProperties.add(disableUserStoreDomain);

        Property disableTenantDomain = new Property();
        disableTenantDomain.setName(DuoAuthenticatorConstants.TENANT_DOMAIN);
        disableTenantDomain.setDisplayName("Disable Tenant Domain");
        disableTenantDomain.setRequired(false);
        disableTenantDomain.setDescription("Configured as true to disable tenant domain");
        disableTenantDomain.setDisplayOrder(7);
        configProperties.add(disableTenantDomain);

        return configProperties;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, String> duoParameters = getAuthenticatorConfig().getParameterMap();
        String requestState = request.getParameter(DuoAuthenticatorConstants.DUO_STATE);
        String requestDuoCode = request.getParameter(DuoAuthenticatorConstants.DUO_CODE);

        try {
            // Step 5: Validate state returned from Duo is the same as the one saved previously.
            // If it isn't return an error
            verifyResponse(context.getProperty(DuoAuthenticatorConstants.DUO_STATE).toString(), requestState);

            AuthenticatedUser authenticatedUser = (AuthenticatedUser) context
                    .getProperty(DuoAuthenticatorConstants.AUTHENTICATED_USER);
            if (authenticatedUser == null) {
                throw new AuthenticationFailedException("Authentication failed!. Cannot proceed further without " +
                        "identifying the user");
            }

            String username = authenticatedUser.getAuthenticatedSubjectIdentifier();

            if (username == null) {
                throw new AuthenticationFailedException("Authentication failed!. Cannot proceed further without " +
                        "identifying the user");
            }
            // Step 6: Exchange the auth duoCode for a Token object
            Token duoToken = duoClient.exchangeAuthorizationCodeFor2FAResult(requestDuoCode, username);

            if (log.isDebugEnabled()) {
                log.debug("Authenticated user: " + username);
                log.debug("Duo Authentication status: " + duoToken.getAuth_result().getStatus_msg());
            }
            if (StringUtils.isNotEmpty(username)) {
                if (Boolean.parseBoolean(duoParameters.get(DuoAuthenticatorConstants.ENABLE_MOBILE_VERIFICATION))) {
                    checkPhoneNumberValidation(context, username);
                } else {
                    context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                }
            } else {
                context.setProperty(DuoAuthenticatorConstants.UNABLE_TO_FIND_VERIFIED_USER, true);
                throw new AuthenticationFailedException("Unable to find verified user from Duo");
            }
        } catch (DuoException e) {
            log.error(DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER, e);
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER, e);
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
}
