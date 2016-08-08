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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
    public static final String ERROR_AKEY = "ERR|The application secret key passed to sign_request() must be at least " +
            AKEY_LEN + " characters.";
    public static final String ERROR_UNKNOWN = "ERR|An unknown error has occurred.";

    public static String signRequest(final String ikey, final String skey, final String akey, final String username) {
        return signRequest(ikey, skey, akey, username, System.currentTimeMillis() / 1000);
    }

    public static String signRequest(final String ikey, final String skey, final String akey, final String username, final long time) {
        final String duo_sig;
        final String app_sig;
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
            duo_sig = signVals(skey, username, ikey, DUO_PREFIX, DUO_EXPIRE, time);
            app_sig = signVals(akey, username, ikey, APP_PREFIX, APP_EXPIRE, time);
        } catch (Exception e) {
            return ERROR_UNKNOWN;
        }
        return duo_sig + ":" + app_sig;
    }

    public static String verifyResponse(final String ikey, final String skey, final String akey, final String sig_response)
            throws DuoWebException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        return verifyResponse(ikey, skey, akey, sig_response, System.currentTimeMillis() / 1000);
    }

    public static String verifyResponse(final String ikey, final String skey, final String akey, final String sig_response, final long time)
            throws DuoWebException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        String auth_user = null;
        String app_user;
        final String[] sigs = sig_response.split(":");
        final String auth_sig = sigs[0];
        final String app_sig = sigs[1];
        auth_user = parseVals(skey, auth_sig, AUTH_PREFIX, ikey, time);
        app_user = parseVals(akey, app_sig, APP_PREFIX, ikey, time);
        if (!auth_user.equals(app_user)) {
            throw new DuoWebException("Authentication failed.");
        }
        return auth_user;
    }

    private static String signVals(final String key, final String username, final String ikey, final String prefix, final int expire, final long time)
            throws InvalidKeyException, NoSuchAlgorithmException {
        final long expire_ts = time + expire;
        final String exp = Long.toString(expire_ts);
        final String val = username + "|" + ikey + "|" + exp;
        final String cookie = prefix + "|" + DuoBase64.encodeBytes(val.getBytes());
        final String sig = DuoUtil.hmacSign(key, cookie);
        return cookie + "|" + sig;
    }

    private static String parseVals(final String key, final String val, final String prefix, final String ikey, final long time)
            throws InvalidKeyException, NoSuchAlgorithmException, IOException, DuoWebException {
        final String[] parts = val.split("\\|");
        if (parts.length != 3) {
            throw new DuoWebException("Invalid response");
        }
        final String u_prefix = parts[0];
        final String u_b64 = parts[1];
        final String u_sig = parts[2];
        final String sig = DuoUtil.hmacSign(key, u_prefix + "|" + u_b64);
        if (!DuoUtil.hmacSign(key, sig).equals(DuoUtil.hmacSign(key, u_sig))) {
            throw new DuoWebException("Invalid response");
        }
        if (!u_prefix.equals(prefix)) {
            throw new DuoWebException("Invalid response");
        }
        final byte[] decoded = DuoBase64.decode(u_b64);
        final String cookie = new String(decoded);
        final String[] cookie_parts = cookie.split("\\|");
        if (cookie_parts.length != 3) {
            throw new DuoWebException("Invalid response");
        }
        final String username = cookie_parts[0];
        final String u_ikey = cookie_parts[1];
        final String expire = cookie_parts[2];
        if (!u_ikey.equals(ikey)) {
            throw new DuoWebException("Invalid response");
        }
        final long expire_ts = Long.parseLong(expire);
        if (time >= expire_ts) {
            throw new DuoWebException("Transaction has expired. Please check that the system time is correct.");
        }
        return username;
    }
}