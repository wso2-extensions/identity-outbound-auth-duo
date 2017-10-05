<%--
  ~ Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
    </head>
    <body>
         <iframe id="duo_iframe"
                 data-host="<%=request.getParameter("duoHost")%>"
                 data-sig-request="<%=request.getParameter("signreq")%>"
                 data-post-action="/commonauth">
         </iframe>
         <style>
             #duo_iframe {
                 width: 100%;
                 min-width: 304px;
                 max-width: 620px;
                 height: 330px;
                 border: none;
             }
         </style>
         <form method="POST" id="duo_form">
             <input type="hidden" name="sessionDataKey" value='<%=request.getParameter("sessionDataKey")%>' />
         </form>
    </body>
    <script src="js/Duo-Web-v2.min.js"></script>
</html>