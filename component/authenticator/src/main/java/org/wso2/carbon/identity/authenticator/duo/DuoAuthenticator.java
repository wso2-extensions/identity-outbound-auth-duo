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

import org.apache.catalina.util.URLEncoder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.duo.internal.DuoAuthenticatorServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return request.getParameter(DuoAuthenticatorConstants.SIG_RESPONSE) != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String username;
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        URLEncoder encoder = new URLEncoder();
        String integrationSecretKey = DuoAuthenticatorConstants.stringGenerator();
        context.setProperty(DuoAuthenticatorConstants.INTEGRATION_SECRET_KEY, integrationSecretKey);
        context.setProperty(DuoAuthenticatorConstants.AUTHENTICATION, DuoAuthenticatorConstants.AUTHENTICATOR_NAME);
        FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
        username = String.valueOf(context.getProperty(DuoAuthenticatorConstants.DUO_USERNAME));

        if (log.isDebugEnabled()) {
            log.debug("user name : " + username);
        }
        if (context.isRetrying()) {
            checkStatusCode(response, context);
        } else if (StringUtils.isNotEmpty(username)) {
            String signRequest = DuoWeb.signRequest(authenticatorProperties.get
                    (DuoAuthenticatorConstants.INTEGRATION_KEY), authenticatorProperties.get
                    (DuoAuthenticatorConstants.SECRET_KEY), integrationSecretKey, username);
            String enrollmentPage = DuoAuthenticatorConstants.DUO_PAGE + "?"
                    + FrameworkConstants.RequestParams.AUTHENTICATOR +
                    "=" + encoder.encode(getName() + ":" + FrameworkConstants.LOCAL_IDP_NAME) + "&" +
                    FrameworkConstants.RequestParams.TYPE + "=" +
                    DuoAuthenticatorConstants.RequestParams.DUO + "&" +
                    DuoAuthenticatorConstants.RequestParams.SIG_REQUEST + "=" +
                    encoder.encode(signRequest) + "&" + FrameworkConstants.SESSION_DATA_KEY + "=" +
                    context.getContextIdentifier() + "&" +
                    DuoAuthenticatorConstants.RequestParams.DUO_HOST + "=" +
                    encoder.encode(authenticatorProperties.get(DuoAuthenticatorConstants.HOST));
            String duoUrl = IdentityUtil.getServerURL(enrollmentPage, false, false);
            try {
                response.sendRedirect(duoUrl);
            } catch (IOException e) {
                throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_REDIRECTING, e);
            }
        } else {
            throw new AuthenticationFailedException("Duo authenticator failed to initialize");
        }
    }

    /**
     * Get DUO user's information.
     *
     * @param context  the authentication context
     * @param username the username
     * @return DUO user information
     * @throws AuthenticationFailedException
     */
    private JSONArray getUserInfo(AuthenticationContext context, String username) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        DuoHttp duoRequest = new DuoHttp(DuoAuthenticatorConstants.HTTP_GET,
                authenticatorProperties.get(DuoAuthenticatorConstants.HOST), DuoAuthenticatorConstants.API_USER);
        duoRequest.addParam(DuoAuthenticatorConstants.DUO_USERNAME, username);
        try {
            duoRequest.signRequest(authenticatorProperties.get(DuoAuthenticatorConstants.ADMIN_IKEY),
                    authenticatorProperties.get(DuoAuthenticatorConstants.ADMIN_SKEY));
            //Execute Duo API request
            Object result = duoRequest.executeRequest();
            JSONArray userInfo = new JSONArray(result.toString());
            if (userInfo.length() == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Couldn't get the DUO user information");
                }
                context.setProperty(DuoAuthenticatorConstants.USER_NOT_REGISTERED_IN_DUO, true);
                throw new AuthenticationFailedException("Couldn't find the user information ");
            }
            return userInfo;
        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_SIGN_REQUEST, e);
        } catch (JSONException e) {
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_JSON, e);
        } catch (Exception e) {
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
                    log.debug("The mobile claim value and registered DUO mobile number should be in same format");
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
                log.debug("Couldn't get the phone number of DUO user");
            }
            context.setProperty(DuoAuthenticatorConstants.MOBILE_NUMBER_NOT_FOUND, true);
            throw new AuthenticationFailedException("User doesn't have a mobile number in DUO for Authentication ");
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
            throw new AuthenticationFailedException("Authentication Failed: An IOException was caught. ", e);
        }
    }

    /**
     * Get DUO custom error page to handle exception.
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

        authenticatedUser = (AuthenticatedUser) authenticationContext.getProperty("authenticatedUser");

        if (authenticatedUser == null) {
            if (log.isDebugEnabled()) {
                log.debug("Authentication failed: Could not find the authenticated user. ");
            }
            throw new AuthenticationFailedException
                    ("Authentication failed: Cannot proceed further without identifying the user. ");
        }
        username = authenticatedUser.getUserName();
        duoParameters = FederatedAuthenticatorUtil.getAuthenticatorConfig(DuoAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (duoParameters != null && duoParameters.get(DuoAuthenticatorConstants.USE_FEDERATED_MOBILE_CLAIM) != null
                && Boolean.parseBoolean(duoParameters.get(DuoAuthenticatorConstants.USE_FEDERATED_MOBILE_CLAIM))) {

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
                UserRealm userRealm = DuoAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId);
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

    /**
     * Get the configuration properties of UI.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property duoHost = new Property();
        duoHost.setDisplayName("Host");
        duoHost.setName(DuoAuthenticatorConstants.HOST);
        duoHost.setDescription("Enter host name of Duo Account");
        duoHost.setRequired(true);
        duoHost.setDisplayOrder(1);
        configProperties.add(duoHost);

        Property integrationKey = new Property();
        integrationKey.setDisplayName("Integration Key");
        integrationKey.setName(DuoAuthenticatorConstants.INTEGRATION_KEY);
        integrationKey.setDescription("Enter Integration Key");
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
        secretKey.setDisplayName("Secret Key");
        secretKey.setName(DuoAuthenticatorConstants.SECRET_KEY);
        secretKey.setDescription("Enter Secret Key");
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

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        Map<String, String> duoParameters = getAuthenticatorConfig().getParameterMap();
        try {
            String username = DuoWeb.verifyResponse(authenticatorProperties.get
                            (DuoAuthenticatorConstants.INTEGRATION_KEY), authenticatorProperties.get
                            (DuoAuthenticatorConstants.SECRET_KEY), context.getProperty
                            (DuoAuthenticatorConstants.INTEGRATION_SECRET_KEY).toString(),
                    request.getParameter(DuoAuthenticatorConstants.SIG_RESPONSE));
            if (log.isDebugEnabled()) {
                log.debug("Authenticated user: " + username);
            }
            if (StringUtils.isNotEmpty(username)) {
                if (Boolean.parseBoolean(duoParameters.get(DuoAuthenticatorConstants.ENABLE_MOBILE_VERIFICATION))) {
                    checkPhoneNumberValidation(context, username);
                } else {
                    context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                }
            } else {
                context.setProperty(DuoAuthenticatorConstants.UNABLE_TO_FIND_VERIFIED_USER, true);
                throw new AuthenticationFailedException("Unable to find verified user from DUO ");
            }
        } catch (DuoWebException | NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            throw new AuthenticationFailedException(DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER, e);
        } catch (JSONException e) {
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
