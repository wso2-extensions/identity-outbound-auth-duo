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
package org.wso2.carbon.identity.authenticator.duo.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.authenticator.duo.DuoAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

/**
 * Service Component for Duo Authenticator
 */
@Component(
        name = "identity.application.authenticator.duo",
        immediate = true
)
public class DuoAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(DuoAuthenticatorServiceComponent.class);
    private RealmService realmService = null;

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            DuoAuthenticator authenticator = new DuoAuthenticator();
            Hashtable<String, String> props = new Hashtable<>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    authenticator, props);
            if (log.isDebugEnabled()) {
                log.debug("DuoAuthenticator bundle is activated");
            }
        } catch (Exception e) {
            log.fatal("Error while activating the DUO authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("DuoAuthenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "org.wso2.carbon.duo.authenticator.realmservice",
            service = RealmService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmSrv) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service.");
        }
        realmService = realmSrv;
        DuoServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmSrv) {

        if (log.isDebugEnabled()) {
            log.debug("Un-setting the Realm Service.");
        }
        realmService = null;
        DuoServiceHolder.getInstance().setRealmService(null);
    }
}
