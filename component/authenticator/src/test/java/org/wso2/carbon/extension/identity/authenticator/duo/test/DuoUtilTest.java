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

import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.authenticator.duo.DuoUtil;

import java.nio.charset.Charset;

import static org.mockito.MockitoAnnotations.initMocks;

/**
 * DuoUtilTest.
 */
public class DuoUtilTest {

    @BeforeMethod
    public void setUp() throws Exception {
        initMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Test(description = "Test case for hmacSign() method.")
    public void testHmacSign() throws Exception {
        Assert.assertEquals(DuoUtil.hmacSign("10", "data"), "1dcb5e97a5b7fc5331d85b68e011de62b900d28f");
    }

    @Test(description = "Test case for hmacSha1() method.")
    public void testHmacSha1() throws Exception {
        String input = "Hello World";
        byte[] bytes = input.getBytes(Charset.forName("UTF-8"));
        Assert.assertNotNull(DuoUtil.hmacSha1(bytes, bytes));
    }

    @Test(description = "Test case for bytesToHex() method.")
    public void testBytesToHex() throws Exception {
        String input = "Hello World";
        byte[] bytes = input.getBytes(Charset.forName("UTF-8"));
        Assert.assertEquals(DuoUtil.bytesToHex(bytes), "48656c6c6f20576f726c64");
    }
}
