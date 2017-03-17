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
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.duo.internal.DuoAuthenticatorServiceComponent;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Mobile based 2nd factor Local Authenticator
 */
public class DuoAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {
    private static final long serialVersionUID = 4438354156955223654L;
    private static Log log = LogFactory.getLog(DuoAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return request.getParameter(DuoAuthenticatorConstants.SIG_RESPONSE) != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        Map<String, String> duoParameters = getAuthenticatorConfig().getParameterMap();
        URLEncoder encoder = new URLEncoder();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String integrationSecretKey = DuoAuthenticatorConstants.stringGenerator();
        String username = getLocalAuthenticatedUser(context);
        context.setProperty(DuoAuthenticatorConstants.INTEGRATION_SECRET_KEY, integrationSecretKey);
        if (StringUtils.isNotEmpty(username)) {
            try {
                username = MultitenantUtils.getTenantAwareUsername(username);
                if(log.isDebugEnabled()) {
                    log.debug("username (tenant aware) : " + username);
                }
                boolean isVerifyPhone = Boolean.parseBoolean(duoParameters.
                        get(DuoAuthenticatorConstants.ENABLE_MOBILE_VERIFICATION));

                // If overriding the username entered with a claim value instead
                if (duoParameters.containsKey(DuoAuthenticatorConstants.OVERRIDE_USERNAME_CLAIM)) {
                    String overrideUsernameClaim = String.valueOf(duoParameters.get(DuoAuthenticatorConstants.OVERRIDE_USERNAME_CLAIM));
                    UserStoreManager userStoreManager = getUserStoreManager(username);
                    username = userStoreManager.getUserClaimValue(username,overrideUsernameClaim, null);
                    if (log.isDebugEnabled()) {
                        log.debug("username (override) : " + username);
                    }
                }

                if (isVerifyPhone) {
                    UserStoreManager userStoreManager = getUserStoreManager(username);
                    String mobile = userStoreManager.getUserClaimValue(username,
                            DuoAuthenticatorConstants.MOBILE_CLAIM, null);
                    if (log.isDebugEnabled()) {
                        log.debug("mobile number : " + mobile);
                    }
                    if (StringUtils.isNotEmpty(mobile)) {
                        JSONArray userAttributes = getUserInfo(context, username);
                        String number = getPhoneNumber(context, userAttributes);
                        if (!mobile.equals(number)) {
                            throw new AuthenticationFailedException(
                                    DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_MISMATCH);
                        }
                    } else {
                        throw new AuthenticationFailedException(
                                DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_NOT_FOUND);
                    }
                }
            } catch (IdentityException | UserStoreException e) {
                throw new AuthenticationFailedException(
                        DuoAuthenticatorConstants.DuoErrors.ERROR_USER_STORE, e);
            } catch (JSONException e) {
                throw new AuthenticationFailedException(
                        DuoAuthenticatorConstants.DuoErrors.ERROR_GETTING_PHONE);
            }
            String sig_request = DuoWeb.signRequest(authenticatorProperties.
                            get(DuoAuthenticatorConstants.INTEGRATION_KEY),
                    authenticatorProperties.get(DuoAuthenticatorConstants.SECRET_KEY), integrationSecretKey, username);
            String enrollmentPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(loginPage, DuoAuthenticatorConstants.DUO_PAGE);
            String duoUrl = enrollmentPage + "?" + FrameworkConstants.RequestParams.AUTHENTICATOR +
                    "=" + encoder.encode(getName() + ":" + FrameworkConstants.LOCAL_IDP_NAME) + "&" +
                    FrameworkConstants.RequestParams.TYPE + "=" +
                    DuoAuthenticatorConstants.RequestParams.DUO + "&" +
                    DuoAuthenticatorConstants.RequestParams.SIG_REQUEST + "=" +
                    encoder.encode(sig_request) + "&" + FrameworkConstants.SESSION_DATA_KEY + "=" +
                    context.getContextIdentifier() + "&" +
                    DuoAuthenticatorConstants.RequestParams.DUO_HOST + "=" +
                    encoder.encode(authenticatorProperties.get(DuoAuthenticatorConstants.HOST));
            try {
                //Redirect to Duo Authentication page
                response.sendRedirect(duoUrl);
            } catch (IOException e) {
                throw new AuthenticationFailedException(
                        DuoAuthenticatorConstants.DuoErrors.ERROR_REDIRECTING, e);
            }
        } else {
            throw new AuthenticationFailedException("Duo authenticator failed to initialize");
        }
    }

    /**
     * get local authenticated user
     *
     * @return username
     */
    private String getLocalAuthenticatedUser(AuthenticationContext context) {
        //Getting the last authenticated local user
        String username = null;
        for (int i = context.getSequenceConfig().getStepMap().size() - 1; i > 0; i--) {
            if (context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser() != null &&
                    context.getSequenceConfig().getStepMap().get(i).getAuthenticatedAutenticator()
                            .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                username = String.valueOf(context.getSequenceConfig().getStepMap().get(i).getAuthenticatedUser());

                if (log.isDebugEnabled()) {
                    log.debug("username : " + username);
                }
                break;
            }
        }
        return username;
    }

    /**
     * get user store manager
     *
     * @return userStoreManager
     */
    private UserStoreManager getUserStoreManager(String username) throws AuthenticationFailedException, UserStoreException {
        UserStoreManager userStoreManager;

        //Get the tenant id of the given user.
        int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
        UserRealm userRealm = DuoAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId);
        if (userRealm != null) {
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } else {
            throw new AuthenticationFailedException(
                    "Cannot find the user realm for the given tenant: " + tenantId);
        }

        return userStoreManager;
    }

    private JSONArray getUserInfo(AuthenticationContext context, String username) throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        Object result;
        DuoHttp duoRequest = new DuoHttp(DuoAuthenticatorConstants.HTTP_GET,
                authenticatorProperties.get(DuoAuthenticatorConstants.HOST), DuoAuthenticatorConstants.API_USER);
        duoRequest.addParam(DuoAuthenticatorConstants.DUO_USERNAME, username);
        try {
            duoRequest.signRequest(authenticatorProperties.get(DuoAuthenticatorConstants.ADMIN_IKEY),
                    authenticatorProperties.get(DuoAuthenticatorConstants.ADMIN_SKEY));
            //Execute Duo API request
            result = duoRequest.executeRequest();
            JSONArray userInfo = new JSONArray(result.toString());
            if (userInfo.length() == 0) {
                throw new AuthenticationFailedException(
                        DuoAuthenticatorConstants.DuoErrors.ERROR_USER_NOT_FOUND);
            }
            return userInfo;
        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_SIGN_REQUEST, e);
        } catch (JSONException e) {
            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_JSON, e);
        } catch (Exception e) {
            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_EXECUTE_REQUEST, e);
        }
    }

    /**
     * get the duo user's phone number
     *
     * @param userInfo user's Attributes
     * @return number  duo user's phone number
     */
    private String getPhoneNumber(AuthenticationContext context, JSONArray userInfo) throws AuthenticationFailedException,
            JSONException {
        JSONArray phoneArray;
        context.setProperty("userInfo", userInfo);
        JSONObject object = userInfo.getJSONObject(0);
        phoneArray = (JSONArray) object.get(DuoAuthenticatorConstants.DUO_PHONES);
        if (phoneArray.length() == 0) {
            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_INVALID);
        } else {
            return ((JSONObject) phoneArray.get(0))
                    .getString(DuoAuthenticatorConstants.DUO_NUMBER);
        }
    }

    /**
     * Get the configuration properties of UI
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
        duoHost.setDisplayOrder(2);
        configProperties.add(integrationKey);

        Property adminIntegrationKey = new Property();
        adminIntegrationKey.setDisplayName("Admin Integration Key");
        adminIntegrationKey.setName(DuoAuthenticatorConstants.ADMIN_IKEY);
        adminIntegrationKey.setDescription("Enter Admin Integration Key");
        adminIntegrationKey.setRequired(false);
        duoHost.setDisplayOrder(3);
        configProperties.add(adminIntegrationKey);

        Property secretKey = new Property();
        secretKey.setDisplayName("Secret Key");
        secretKey.setName(DuoAuthenticatorConstants.SECRET_KEY);
        secretKey.setDescription("Enter Secret Key");
        secretKey.setRequired(true);
        secretKey.setConfidential(true);
        duoHost.setDisplayOrder(4);
        configProperties.add(secretKey);

        Property adminSecretKey = new Property();
        adminSecretKey.setName(DuoAuthenticatorConstants.ADMIN_SKEY);
        adminSecretKey.setDisplayName("Admin Secret Key");
        adminSecretKey.setRequired(false);
        adminSecretKey.setDescription("Enter Admin Secret Key");
        adminSecretKey.setConfidential(true);
        duoHost.setDisplayOrder(5);
        configProperties.add(adminSecretKey);

        return configProperties;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = context
                .getAuthenticatorProperties();
        String username;
        try {
            username = DuoWeb.verifyResponse(authenticatorProperties.get(DuoAuthenticatorConstants.INTEGRATION_KEY),
                    authenticatorProperties.get(DuoAuthenticatorConstants.SECRET_KEY),
                    context.getProperty(DuoAuthenticatorConstants.INTEGRATION_SECRET_KEY).toString(),
                    request.getParameter(DuoAuthenticatorConstants.SIG_RESPONSE));
            if (log.isDebugEnabled()) {
                log.debug("Authenticated user: " + username);
            }
        } catch (DuoWebException | NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            throw new AuthenticationFailedException(
                    DuoAuthenticatorConstants.DuoErrors.ERROR_VERIFY_USER, e);
        }
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
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
}