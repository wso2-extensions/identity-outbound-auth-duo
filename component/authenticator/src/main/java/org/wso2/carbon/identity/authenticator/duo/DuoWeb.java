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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Duo Web class.
 */
public final class DuoWeb {
    private static final String DUO_PREFIX = "TX";
    private static final String APP_PREFIX = "APP";
    private static final String AUTH_PREFIX = "AUTH";

    private static final int DUO_EXPIRE = 300;
    private static final int APP_EXPIRE = 3600;

    private static final int IKEY_LEN = 20;
    private static final int SKEY_LEN = 40;
    private static final int AKEY_LEN = 40;

    public static final String ERROR_USER = "ERR|The username passed to sign_request() is invalid.";
    public static final String ERROR_IKEY = "ERR|The Duo integration key passed to sign_request() is invalid.";
    public static final String ERROR_SKEY = "ERR|The Duo secret key passed to sign_request() is invalid.";
    public static final String ERROR_AKEY = "ERR|The application secret key passed to sign_request() must be at least" +
            " " + AKEY_LEN + " characters.";
    public static final String ERROR_UNKNOWN = "ERR|An unknown error has occurred.";

    public static String signRequest(final String ikey, final String skey, final String akey, final String username) {
        return signRequest(ikey, skey, akey, username, System.currentTimeMillis() / 1000);
    }

    public static String signRequest(final String ikey, final String skey, final String akey, final String username,
                                     final long time) {
        final String duoSig;
        final String appSig;
        if (username.equals("")) {
            return ERROR_USER;
        }
        if (username.indexOf('|') != -1) {
            return ERROR_USER;
        }
        if (ikey.equals("") || ikey.length() != IKEY_LEN) {
            return ERROR_IKEY;
        }
        if (skey.equals("") || skey.length() != SKEY_LEN) {
            return ERROR_SKEY;
        }
        if (akey.equals("") || akey.length() < AKEY_LEN) {
            return ERROR_AKEY;
        }
        try {
            duoSig = signVals(skey, username, ikey, DUO_PREFIX, DUO_EXPIRE, time);
            appSig = signVals(akey, username, ikey, APP_PREFIX, APP_EXPIRE, time);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return ERROR_UNKNOWN;
        }
        return duoSig + ":" + appSig;
    }

    public static String verifyResponse(final String ikey, final String skey, final String akey,
                                        final String sigResponse)
            throws DuoWebException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        return verifyResponse(ikey, skey, akey, sigResponse, System.currentTimeMillis() / 1000);
    }

    public static String verifyResponse(final String ikey, final String skey, final String akey,
                                        final String sigResponse, final long time)
            throws DuoWebException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        String authUser = null;
        String appUser;
        final String[] sigs = sigResponse.split(":");
        final String authSig = sigs[0];
        final String appSig = sigs[1];
        authUser = parseVals(skey, authSig, AUTH_PREFIX, ikey, time);
        appUser = parseVals(akey, appSig, APP_PREFIX, ikey, time);
        if (!authUser.equals(appUser)) {
            throw new DuoWebException("Authentication failed.");
        }
        return authUser;
    }

    private static String signVals(final String key, final String username, final String ikey, final String prefix,
                                   final int expire, final long time)
            throws InvalidKeyException, NoSuchAlgorithmException {
        final long expireTs = time + expire;
        final String exp = Long.toString(expireTs);
        final String val = username + "|" + ikey + "|" + exp;
        final String cookie = prefix + "|" + DuoBase64.encodeBytes(val.getBytes(StandardCharsets.UTF_8));
        final String sig = DuoUtil.hmacSign(key, cookie);
        return cookie + "|" + sig;
    }

    private static String parseVals(final String key, final String val, final String prefix, final String ikey,
                                    final long time)
            throws InvalidKeyException, NoSuchAlgorithmException, IOException, DuoWebException {
        final String[] parts = val.split("\\|");
        if (parts.length != 3) {
            throw new DuoWebException("Invalid response");
        }
        final String uPrefix = parts[0];
        final String uB64 = parts[1];
        final String uSig = parts[2];
        final String sig = DuoUtil.hmacSign(key, uPrefix + "|" + uB64);
        if (!DuoUtil.hmacSign(key, sig).equals(DuoUtil.hmacSign(key, uSig))) {
            throw new DuoWebException("Invalid response");
        }
        if (!uPrefix.equals(prefix)) {
            throw new DuoWebException("Invalid response");
        }
        final byte[] decoded = DuoBase64.decode(uB64);
        final String cookie = new String(decoded, StandardCharsets.UTF_8);
        final String[] cookieParts = cookie.split("\\|");
        if (cookieParts.length != 3) {
            throw new DuoWebException("Invalid response");
        }
        final String username = cookieParts[0];
        final String uIkey = cookieParts[1];
        final String expire = cookieParts[2];
        if (!uIkey.equals(ikey)) {
            throw new DuoWebException("Invalid response");
        }
        final long expireTs = Long.parseLong(expire);
        if (time >= expireTs) {
            throw new DuoWebException("Transaction has expired. Please check that the system time is correct.");
        }
        return username;
    }
}
