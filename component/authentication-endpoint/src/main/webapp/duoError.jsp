<%--
 ~ Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 ~
 ~ WSO2 LLC. licenses this file to you under the Apache License,
 ~ Version 2.0 (the "License"); you may not use this file except
 ~ in compliance with the License.
 ~ You may obtain a copy of the License at
 ~
 ~ http://www.apache.org/licenses/LICENSE-2.0
 ~
 ~ Unless required by applicable law or agreed to in writing,
 ~ software distributed under the License is distributed on an
 ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 ~ KIND, either express or implied. See the License for the
 ~ specific language governing permissions and limitations
 ~ under the License.
--%>
<%@ page import="java.io.File" %>
<%@ page import="java.util.Map" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="org.wso2.carbon.identity.mgt.endpoint.util.IdentityManagementEndpointUtil" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ include file="includes/localize.jsp" %>

    <%
        request.getSession().invalidate();
        String queryString = request.getQueryString();
        Map<String, String> idpAuthenticatorMapping = null;
        if (request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP) != null) {
            idpAuthenticatorMapping = (Map<String, String>) request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP);
        }

        String errorMessage = IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "something.went.wrong.during.authentication");
        String authenticationFailed = "false";

        if (Boolean.parseBoolean(request.getParameter(Constants.AUTH_FAILURE))) {
            authenticationFailed = "true";

            if (request.getParameter(Constants.AUTH_FAILURE_MSG) != null) {
                errorMessage = request.getParameter(Constants.AUTH_FAILURE_MSG);

                if (errorMessage.equalsIgnoreCase("user.not.registered")) {
                    errorMessage = IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "error.user.not.registered");
                } else if (errorMessage.equalsIgnoreCase("unable.to.get.duo.mobileNumber")) {
                    errorMessage = IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "error.mobile.not.found.duo");
                } else if (errorMessage.equalsIgnoreCase("unable.to.find.number")) {
                    errorMessage = IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "error.mobile.not.found");
                } else if (errorMessage.equalsIgnoreCase("number.mismatch")) {
                    errorMessage = IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "error.number.mismatch.duo");
                } else if (errorMessage.equalsIgnoreCase("user.not.found")) {
                    errorMessage = IdentityManagementEndpointUtil.i18n(recoveryResourceBundle, "error.duo.user.not.found");
                }
            }
        }
    %>

<html>
    <head>
      <!-- header -->
      <%
          File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
          if (headerFile.exists()) {
      %>
      <jsp:include page="extensions/header.jsp" />
      <% } else { %>
      <jsp:directive.include file="includes/header.jsp" />
      <% } %>

      <!--[if lt IE 9]>
      <script src="js/html5shiv.min.js"></script>
      <script src="js/respond.min.js"></script>
      <![endif]-->
    </head>

    <body>
      <main class="center-segment">
        <div class="ui container medium center aligned middle aligned">
          <!-- product-title -->
          <%
              File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
              if (productTitleFile.exists()) {
          %>
          <jsp:include page="extensions/product-title.jsp" />
          <% } else { %>
          <jsp:directive.include file="includes/product-title.jsp" />
          <% } %>

          <div class="ui segment">
            <!-- page content -->
            <h2>Failed Authentication with Duo</h2>
            <div class="ui divider hidden"></div>
              <%
                if ("true".equals(authenticationFailed)) {
              %>
            <div class="ui negative message" id="failed-msg"><%=errorMessage%></div>
            <% } %>
          </div>
        </div>
      </main>

      <!-- product-footer -->
      <%
        File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
        if (productFooterFile.exists()) {
      %>
      <jsp:include page="extensions/product-footer.jsp" />
      <% } else { %>
      <jsp:directive.include file="includes/product-footer.jsp" />
      <% } %>

      <!-- footer -->
      <%
        File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
        if (footerFile.exists()) {
      %>
      <jsp:include page="extensions/footer.jsp" />
      <% } else { %>
      <jsp:directive.include file="includes/footer.jsp" />
      <% } %>
    </body>
</html>
