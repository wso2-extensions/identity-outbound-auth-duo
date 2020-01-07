/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.extension.identity.authenticator.duo.test;

import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.duo.DuoAuthenticator;
import org.wso2.carbon.identity.authenticator.duo.DuoAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.duo.DuoHttp;
import org.wso2.carbon.identity.authenticator.duo.internal.DuoAuthenticatorServiceComponent;
import org.wso2.carbon.identity.authenticator.duo.internal.DuoServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

/**
 * Test case for Mobile based 2nd factor Local Authenticator.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({IdentityTenantUtil.class, DuoAuthenticatorServiceComponent.class, FrameworkUtils.class,
        IdentityUtil.class, DuoHttp.class, OkHttpClient.class, Request.class, Response.class,
        FederatedAuthenticatorUtil.class, DuoServiceHolder.class})
public class DuoAuthenticatorTest {

    private DuoAuthenticator duoAuthenticator;

    @Spy
    private AuthenticationContext context;

    @Mock
    private SequenceConfig sequenceConfig;

    @Mock
    private Map<Integer, StepConfig> mockedMap;

    @Mock
    private StepConfig stepConfig;

    @Mock
    private AuthenticatorConfig authenticatorConfig;

    @Mock
    private LocalApplicationAuthenticator localApplicationAuthenticator;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private DuoServiceHolder serviceHolder;

    @BeforeMethod
    public void setUp() throws Exception {

        duoAuthenticator = new DuoAuthenticator();
        initMocks(this);
        mockStatic(DuoServiceHolder.class);
        when(DuoServiceHolder.getInstance()).thenReturn(serviceHolder);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test(description = "Test case for canHandle() method true case.")
    public void testCanHandleTrue() {

        when(httpServletRequest.getParameter(DuoAuthenticatorConstants.SIG_RESPONSE)).thenReturn("response");
        Assert.assertEquals(duoAuthenticator.canHandle(httpServletRequest), true);
    }

    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() {

        when(httpServletRequest.getParameter(DuoAuthenticatorConstants.SIG_RESPONSE)).thenReturn(null);
        Assert.assertEquals(duoAuthenticator.canHandle(httpServletRequest), false);
    }

    @Test(description = "Test case for getFriendlyName() method.")
    public void testGetFriendlyName() {

        Assert.assertEquals(duoAuthenticator.getFriendlyName(),
                DuoAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test(description = "Test case for getName() method.")
    public void testGetName() {

        Assert.assertEquals(duoAuthenticator.getName(),
                DuoAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test(description = "Test case for retryAuthenticationEnabled() method.")
    public void testRetryAuthenticationEnabled() throws Exception {

        Assert.assertEquals(Whitebox.invokeMethod(duoAuthenticator, "retryAuthenticationEnabled"), true);
    }

    @Test(description = "Test case for getContextIdentifier() method.")
    public void testGetContextIdentifier() {

        when(httpServletRequest.getParameter(DuoAuthenticatorConstants.SESSION_DATA_KEY)).thenReturn("abc");
        Assert.assertEquals(duoAuthenticator.getContextIdentifier(httpServletRequest),
                "abc");
    }

    @Test(description = "Test case for getMobileClaimValue() method.")
    public void testGetMobileClaimValue() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        mockStatic(DuoAuthenticatorServiceComponent.class);
        mockStatic(FederatedAuthenticatorUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(-1234);
        when(serviceHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");
        when((AuthenticatedUser) context.getProperty("authenticatedUser")).thenReturn(authenticatedUser);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        DuoAuthenticatorConstants.MOBILE_CLAIM, null)).thenReturn("0771234565");
        Assert.assertEquals(Whitebox.invokeMethod(duoAuthenticator, "getMobileClaimValue", context),
                "0771234565");
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class}, description = "Test case for " +
            "getMobileClaimValue() method with exception")
    public void testGetMobileClaimValueWithException() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        mockStatic(DuoAuthenticatorServiceComponent.class);
        when(IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(0);
        when(serviceHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        DuoAuthenticatorConstants.MOBILE_CLAIM, null)).thenReturn("0771234565");
        Assert.assertEquals(Whitebox.invokeMethod(duoAuthenticator, "getMobileClaimValue", context),
                "Cannot find the user realm for the given tenant: 0");
    }

    @Test(description = "Test case for checkStatusCode() with number mis match")
    public void testCheckStatusCodeWithNumberMismatch() throws Exception {

        mockStatic(FrameworkUtils.class);
        mockStatic(IdentityUtil.class);
        context.setProperty(DuoAuthenticatorConstants.NUMBER_MISMATCH, true);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn
                (null);
        when(IdentityUtil.getServerURL(DuoAuthenticatorConstants.DUO_ERROR_PAGE, false,
                false)).thenReturn(DuoAuthenticatorConstants.DUO_ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        Whitebox.invokeMethod(duoAuthenticator, "checkStatusCode", httpServletResponse, context);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_MISMATCH));
    }

    @Test(description = "Test case for getErrorPage() method")
    public void testGetErrorPage() throws Exception {

        mockStatic(FrameworkUtils.class);
        mockStatic(IdentityUtil.class);
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn
                (null);
        Assert.assertNull(Whitebox.invokeMethod(duoAuthenticator, "getErrorPage", context));
    }

    @Test(description = "Test case for isValidPhoneNumber() method")
    public void testIsValidPhoneNumber() throws Exception {

        JSONObject jo = new JSONObject();
        jo.put("number", "0771234567");
        JSONArray jsonArray = new JSONArray();
        jsonArray.put(jo);
        Assert.assertEquals(Whitebox.invokeMethod(duoAuthenticator, "isValidPhoneNumber",
                context, jsonArray, "0771234567"), true);
    }

    @Test(description = "Test case for isValidPhoneNumber() method false")
    public void testIsValidPhoneNumberWithFalse() throws Exception {

        JSONObject jo = new JSONObject();
        jo.put("number", "");
        JSONArray jsonArray = new JSONArray();
        jsonArray.put(jo);
        Assert.assertEquals(Whitebox.invokeMethod(duoAuthenticator, "isValidPhoneNumber",
                context, jsonArray, "0771234567"), false);
    }

    @Test(description = "Test case for getConfigurationProperties() method.")
    public void testGetConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        Property duoHost = new Property();
        configProperties.add(duoHost);
        Property integrationKey = new Property();
        configProperties.add(integrationKey);
        Property adminIntegrationKey = new Property();
        configProperties.add(adminIntegrationKey);
        Property secretKey = new Property();
        configProperties.add(secretKey);
        Property adminSecretKey = new Property();
        configProperties.add(adminSecretKey);
        Property disableUserStoreDomain = new Property();
        configProperties.add(disableUserStoreDomain);
        Property disableTenantDomain = new Property();
        configProperties.add(disableTenantDomain);
        Assert.assertEquals(configProperties.size(), duoAuthenticator.getConfigurationProperties().size());
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }
}
