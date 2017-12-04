/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.slack.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultString;
import se.curity.identityserver.sdk.config.annotation.DefaultURI;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.SessionManager;

import java.net.URI;

import static io.curity.identityserver.plugin.slack.authentication.Constants.USERS_READ;

@SuppressWarnings("InterfaceNeverImplemented")
public interface SlackAuthenticatorPluginConfig extends Configuration {
    @Description("client id")
    String getClientId();

    @Description("Secret key used for communication with slack")
    String getClientSecret();

    @Description("URL to the Slack authorization endpoint")
    @DefaultURI("https://slack.com/oauth/authorize")
    URI getAuthorizationEndpoint();

    @Description("URL to the Slack access token endpoint")
    @DefaultURI("https://slack.com/api/oauth.access")
    URI getTokenEndpoint();

    @Description("A space-separated list of scopes to request from Slack")
    @DefaultString(USERS_READ)
    String getScope();

    @Description("Slack team ID of a workspace to attempt to restrict to")
    @DefaultString("")
    String getTeam();

    SessionManager getSessionManager();

}
