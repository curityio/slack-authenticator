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


    Optional<Scopes> getScope();

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

            @Description("Manage access to information about your public channels")
            @DefaultEnum("NONE")
            Access getChannelAccess();
        }

        enum Access
        {
            NONE, READ, WRITE
        }
    }

    enum Access
    {
        NONE, READ, WRITE
    }

    @Description("Manage information about your public channels")
    Optional<ManageChannel> getManageChannel();

    interface ManageChannel
    {
        @Description("Request a scope (channels:history) that grants access to content in your public channels")
        @DefaultBoolean(false)
        boolean isChannelHistory();

        @Description("Manage access to information about your public channels")
        @DefaultEnum("NONE")
        Access getChannelAccess();
    }

    @Description("Request a scope (chat:write:bot) that grants access to send messages as your slack app")
    @DefaultBoolean(false)
    boolean isChatWriteBotAccess();

    @Description("Request a scope (chat:write:user) that grants access to send messages as you")
    @DefaultBoolean(false)
    boolean isChatWriteUserAccess();

    @Description("Request a scope (client) that grants access to receive all events from a workspace in realtime")
    @DefaultBoolean(false)
    boolean isClientAccess();

    @Description("Request a scope (commands) that grants access to add commands to a workspace")
    @DefaultBoolean(false)
    boolean isCommandsAccess();

    @Description("Manage access to your workspace’s Do Not Disturb settings")
    @DefaultEnum("NONE")
    Access getDoNotDisturbAccess();

    @Description("Request a scope (emoji:read) that grants access to your workspace’s emoji")
    @DefaultBoolean(false)
    boolean isEmojiAccess();

    @Description("Manage access to your workspace’s files, comments, and associated information")
    @DefaultEnum("NONE")
    Access getFilesAccess();


    @Description("Manage information about your private channels")
    Optional<ManageGroups> getManageGroups();

    interface ManageGroups
    {
        @Description("Request a scope (groups:history) that grants access to content in your private channels")
        @DefaultBoolean(false)
        boolean isGroupsHistory();

        @Description("Manage access to information about your private channels")
        @DefaultEnum("NONE")
        Access getGroupsAccess();
    }

    @Description("Request a scope (identity) that grants access to confirm your identity")
    @DefaultBoolean(false)
    boolean isIdentityAccess();

    @Description("Request a scope (identity.avatar) that grants access to view your Slack avatar")
    @DefaultBoolean(false)
    boolean isViewAvatar();

    @Description("Manage information about your direct messages")
    Optional<ManageDirectMessages> getManageDirectMessages();

    interface ManageDirectMessages
    {
        @Description("Request a scope (im:history) that grants access to content in your direct messages")
        @DefaultBoolean(false)
        boolean isDirectMessagesHistory();

        @Description("Manage access to content in your direct messages")
        @DefaultEnum("NONE")
        Access getDirectMessagesAccess();
    }

    @Description("Request a scope (incoming-webhook) that grants access to create one-way webhooks to post messages to a specific channel")
    @DefaultBoolean(false)
    boolean isCreateWebhook();

    @Description("Manage URLs in messages")
    @DefaultEnum("NONE")
    Access getLinksAccess();


    @Description("Manage information about your group messages")
    Optional<ManageGroupMessages> getManageGroupMessages();

    interface ManageGroupMessages
    {
        @Description("Request a scope (mpim:history) that grants access your group messages")
        @DefaultBoolean(false)
        boolean isGroupMessagesHistory();

        @Description("Manage access to information about your group messages")
        @DefaultEnum("NONE")
        Access getGroupMessagesAccess();
    }

    @Description("Manage access to your workspace’s pinned content and associated information")
    @DefaultEnum("NONE")
    Access getPinsAccess();

    @Description("Request a scope (post) that grants access to post messages to a workspace")
    @DefaultBoolean(false)
    boolean isPostMessage();

    @Description("Manage access to your workspace’s content with emoji reactions")
    @DefaultEnum("NONE")
    Access getReactionsAccess();

    @Description("Request a scope (read) that grants read access to all content in a workspace")
    @DefaultBoolean(false)
    boolean isReadAccess();

    @Description("Manage access to reminders created by you or for you")
    @DefaultEnum("NONE")
    Access getRemindersAccess();

    @Description("Request a scope (search:read) that grants access to search your workspace’s content")
    @DefaultBoolean(false)
    boolean isSearchAccess();

    @Description("Manage access to your starred messages and files")
    @DefaultEnum("NONE")
    Access getStarsAccess();

    @Description("Request a scope (team:read) that grants access to information about your workspace")
    @DefaultBoolean(false)
    boolean isTeamAccess();

    @Description("Request a scope (tokens.basic) that grants access to execute methods without needing a scope")
    @DefaultBoolean(false)
    boolean isBasicTokenAccess();

    @Description("Manage access to basic information about your User Groups")
    @DefaultEnum("NONE")
    Access getUserGroupsAccess();

    @Description("Manage access to your profile and your workspace’s profile fields")
    @DefaultEnum("NONE")
    Access getUserProfileAccess();

    @Description("Request a scope (users:read.email) that grants access to view email addresses of people on your workspace")
    @DefaultBoolean(false)
    boolean isEmailAccess();

    @Description("Request a scope (users:write) that grants access to modify your profile information")
    @DefaultBoolean(false)
    boolean isModifyUserProfile();


    SessionManager getSessionManager();

    ExceptionFactory getExceptionFactory();

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    WebServiceClientFactory getWebServiceClientFactory();

    Json getJson();

}
