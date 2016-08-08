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

import com.squareup.okhttp.*;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class DuoHttp {
    private String method;
    private String host;
    private String uri;
    private Headers.Builder headers;
    Map<String, String> params = new HashMap<String, String>();
    private Proxy proxy;
    private int timeout = 60;

    public static SimpleDateFormat RFC_2822_DATE_FORMAT
            = new SimpleDateFormat("EEE', 'dd' 'MMM' 'yyyy' 'HH:mm:ss' 'Z",
            Locale.US);

    public static MediaType FORM_ENCODED = MediaType.parse("application/x-www-form-urlencoded");

    public DuoHttp(String in_method, String in_host, String in_uri) {
        method = in_method.toUpperCase();
        host = in_host;
        uri = in_uri;
        headers = new Headers.Builder();
        headers.add("Host", host);
        proxy = null;
    }

    public DuoHttp(String in_method, String in_host, String in_uri, int timeout) {
        this(in_method, in_host, in_uri);
        this.timeout = timeout;
    }

    public Object executeRequest() throws Exception {
        JSONObject result = new JSONObject(executeRequestRaw());
        if (!result.getString("stat").equals("OK")) {
            throw new Exception("Duo error code ("
                    + result.getInt("code")
                    + "): "
                    + result.getString("message"));
        }
        return result.get("response");
    }

    public String executeRequestRaw() throws Exception {
        Response response = executeHttpRequest();
        return response.body().string();
    }

    public Response executeHttpRequest() throws Exception {
        String url = "https://" + host + uri;
        String queryString = createQueryString();
        Request.Builder builder = new Request.Builder();
        if (method.equals("POST")) {
            builder.post(RequestBody.create(FORM_ENCODED, queryString));
        } else if (method.equals("PUT")) {
            builder.put(RequestBody.create(FORM_ENCODED, queryString));
        } else if (method.equals("GET")) {
            if (queryString.length() > 0) {
                url += "?" + queryString;
            }
            builder.get();
        } else if (method.equals("DELETE")) {
            if (queryString.length() > 0) {
                url += "?" + queryString;
            }
            builder.delete();
        } else {
            throw new UnsupportedOperationException("Unsupported method: "
                    + method);
        }
        Request request = builder.url(url)
                .build();
        // Set up client.
        OkHttpClient httpclient = new OkHttpClient();
        if (proxy != null) {
            httpclient.setProxy(proxy);
        }
        httpclient.setConnectTimeout(timeout, TimeUnit.SECONDS);
        httpclient.setWriteTimeout(timeout, TimeUnit.SECONDS);
        httpclient.setReadTimeout(timeout, TimeUnit.SECONDS);
        // finish and execute request
        builder.headers(headers.build());
        return httpclient.newCall(builder.build())
                .execute();
    }

    public void signRequest(String ikey, String skey)
            throws UnsupportedEncodingException {
        signRequest(ikey, skey, 2);
    }

    public void signRequest(String ikey, String skey, int sig_version)
            throws UnsupportedEncodingException {
        String date = formatDate(new Date());
        String canon = canonRequest(date, sig_version);
        String sig = signHMAC(skey, canon);
        String auth = ikey + ":" + sig;
        String header = "Basic " + DuoBase64.encodeBytes(auth.getBytes());
        addHeader("Authorization", header);
        if (sig_version == 2) {
            addHeader("Date", date);
        }
    }

    protected String signHMAC(String skey, String msg) {
        try {
            byte[] sig_bytes = DuoUtil.hmacSha1(skey.getBytes(), msg.getBytes());
            String sig = DuoUtil.bytesToHex(sig_bytes);
            return sig;
        } catch (Exception e) {
            return "";
        }
    }

    private synchronized String formatDate(Date date) {
        // Could use ThreadLocal or a pool of format objects instead
        // depending on the needs of the application.
        return RFC_2822_DATE_FORMAT.format(date);
    }

    public void addHeader(String name, String value) {
        headers.add(name, value);
    }

    public void addParam(String name, String value) {
        params.put(name, value);
    }

    public void setProxy(String host, int port) {
        proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    }

    protected String canonRequest(String date, int sig_version)
            throws UnsupportedEncodingException {
        String canon = "";
        if (sig_version == 2) {
            canon += date + "\n";
        }
        canon += method.toUpperCase() + "\n";
        canon += host.toLowerCase() + "\n";
        canon += uri + "\n";
        canon += createQueryString();
        return canon;
    }

    private String createQueryString()
            throws UnsupportedEncodingException {
        ArrayList<String> args = new ArrayList<String>();
        ArrayList<String> keys = new ArrayList<String>();

        for (String key : params.keySet()) {
            keys.add(key);
        }
        Collections.sort(keys);
        for (String key : keys) {
            String name = URLEncoder
                    .encode(key, "UTF-8")
                    .replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~");
            String value = URLEncoder
                    .encode(params.get(key), "UTF-8")
                    .replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~");
            args.add(name + "=" + value);
        }
        return DuoUtil.join(args.toArray(), "&");
    }
}