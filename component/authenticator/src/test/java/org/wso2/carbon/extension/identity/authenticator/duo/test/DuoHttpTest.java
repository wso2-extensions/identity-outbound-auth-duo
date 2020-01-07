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

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.authenticator.duo.DuoHttp;
import org.wso2.carbon.identity.authenticator.duo.DuoUtil;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

/**
 * DuoHttpTest.
 */
@PrepareForTest({DuoUtil.class})
public class DuoHttpTest {
    private DuoHttp duoHttp;

    @BeforeMethod
    public void setUp() throws Exception {
        duoHttp = new DuoHttp("GET", "localhost", "/services/admin");
        initMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Test(description = "Test case for signRequest() method.")
    public void testSignRequest() throws Exception {
        mockStatic(DuoUtil.class);

        duoHttp.signRequest("12", "10");
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();
        Assert.assertNotNull(Whitebox.invokeMethod(duoHttp, "canonRequest",
                dateFormat.format(date), 2));
    }

    @Test(description = "Test case for createQueryString() method.")
    public void testCreateQueryString() throws Exception {
        mockStatic(DuoUtil.class);
        Assert.assertNull(Whitebox.invokeMethod(duoHttp, "createQueryString"));
    }
}
