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
import se.curity.identityserver.sdk.config.OneOf;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.util.Optional;

@SuppressWarnings("InterfaceNeverImplemented")
public interface SlackAuthenticatorPluginConfig extends Configuration
{
    @Description("The client applications identifier")
    String getClientId();

    @Description("The secret of the client application")
    String getClientSecret();

    @Description("The HTTP client with any proxy and TLS settings that will be used to connect to slack")
    Optional<HttpClient> getHttpClient();

    @Description("Slack team ID of a workspace to attempt to restrict to")
    Optional<String> getTeam();


    Scopes getScope();

    interface Scopes extends OneOf
    {
        Optional<@DefaultBoolean(true) Boolean> isAdministerWorkspace();

        Optional<OtherScopes> isOtherScopes();

        interface OtherScopes
        {
            @Description("Manage information about your public channels")
            Optional<ManageChannel> getManageChannel();

        }

        interface ManageChannel
        {
            @Description("Access content in your public channels")
            @DefaultBoolean(false)
            boolean getChannelHistory();

            @DefaultEnum("NONE")
            Access getChannelAccess();
        }

        enum Access
        {
            NONE, READ, WRITE
        }
    }

    SessionManager getSessionManager();

    ExceptionFactory getExceptionFactory();

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    WebServiceClientFactory getWebServiceClientFactory();

    Json getJson();

}
