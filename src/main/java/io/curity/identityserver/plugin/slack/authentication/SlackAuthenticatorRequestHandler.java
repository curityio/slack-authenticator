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

package io.curity.identityserver.plugin.slack.authentication;

import io.curity.identityserver.plugin.slack.config.SlackAuthenticatorPluginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.RedirectStatusCode;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static io.curity.identityserver.plugin.slack.descriptor.SlackAuthenticatorPluginDescriptor.CALLBACK;

public class SlackAuthenticatorRequestHandler implements AuthenticatorRequestHandler<Request>
{
    private static final Logger _logger = LoggerFactory.getLogger(SlackAuthenticatorRequestHandler.class);
    private static final String AUTHORIZATION_ENDPOINT = "https://slack.com/oauth/authorize";

    private final SlackAuthenticatorPluginConfig _config;
    private final AuthenticatorInformationProvider _authenticatorInformationProvider;
    private final ExceptionFactory _exceptionFactory;

    public SlackAuthenticatorRequestHandler(SlackAuthenticatorPluginConfig config)
    {
        _config = config;
        _exceptionFactory = config.getExceptionFactory();
        _authenticatorInformationProvider = config.getAuthenticatorInformationProvider();
    }

    @Override
    public Optional<AuthenticationResult> get(Request request, Response response)
    {
        _logger.debug("GET request received for authentication authentication");

        String redirectUri = createRedirectUri();
        String state = UUID.randomUUID().toString();
        Map<String, Collection<String>> queryStringArguments = new LinkedHashMap<>(5);
        Set<String> scopes = new LinkedHashSet<>(7);

        _config.getSessionManager().put(Attribute.of("state", state));

        queryStringArguments.put("client_id", Collections.singleton(_config.getClientId()));
        queryStringArguments.put("redirect_uri", Collections.singleton(redirectUri));
        queryStringArguments.put("state", Collections.singleton(state));
        queryStringArguments.put("response_type", Collections.singleton("code"));
        _config.getTeam().ifPresent(team ->
                queryStringArguments.put("team", Collections.singleton(team))
        );

        handleScopes(scopes);

        queryStringArguments.put("scope", Collections.singleton(String.join(" ", scopes)));

        _logger.debug("Redirecting to {} with query string arguments {}", AUTHORIZATION_ENDPOINT,
                queryStringArguments);

        throw _exceptionFactory.redirectException(AUTHORIZATION_ENDPOINT,
                RedirectStatusCode.MOVED_TEMPORARILY, queryStringArguments, false);
    }

    private String createRedirectUri()
    {
        try
        {
            URI authUri = _authenticatorInformationProvider.getFullyQualifiedAuthenticationUri();

            return new URL(authUri.toURL(), authUri.getPath() + "/" + CALLBACK).toString();
        }
        catch (MalformedURLException e)
        {
            throw _exceptionFactory.internalServerException(ErrorCode.INVALID_REDIRECT_URI,
                    "Could not create redirect URI");
        }
    }

    static private void addScopeIfApplicable(Set<String> scopes, String scope, boolean add)
    {
        if (add)
        {
            scopes.add(scope);
        }
    }

    private void handleScopes(Set<String> scopes)
    {
        //add default scope to get user profile info
        scopes.add("users:read");

        _config.getScope().isAdministerWorkspace().ifPresent(admin ->
        {
            addScopeIfApplicable(scopes, "admin", admin);
        });

        _config.getScope().isManageScopes().ifPresent(manageScopes ->
        {
            addScopeIfApplicable(scopes, "chat:write:bot", manageScopes.isChatWriteBotAccess());
            addScopeIfApplicable(scopes, "chat:write:user", manageScopes.isChatWriteUserAccess());
            addScopeIfApplicable(scopes, "client", manageScopes.isClientAccess());
            addScopeIfApplicable(scopes, "commands", manageScopes.isCommandsAccess());
            addScopeIfApplicable(scopes, "emoji:read", manageScopes.isEmojiAccess());
            addScopeIfApplicable(scopes, "dnd:read", "dnd:write", manageScopes.getDoNotDisturbAccess());
            addScopeIfApplicable(scopes, "files:read", "files:write", manageScopes.getFilesAccess());
            addScopeIfApplicable(scopes, "incoming-webhook", manageScopes.isCreateWebhook());
            addScopeIfApplicable(scopes, "links:read", "links:write", manageScopes.getLinksAccess());
            addScopeIfApplicable(scopes, "links:read", "links:write", manageScopes.getLinksAccess());
            addScopeIfApplicable(scopes, "identity", manageScopes.isIdentityAccess());
            addScopeIfApplicable(scopes, "identity.avatar", manageScopes.isViewAvatar());
            addScopeIfApplicable(scopes, "identity.email", manageScopes.isViewEmail());
            addScopeIfApplicable(scopes, "identity.team", manageScopes.isViewTeam());
            addScopeIfApplicable(scopes, "pins:read", "pins:write", manageScopes.getPinsAccess());
            addScopeIfApplicable(scopes, "post", manageScopes.isPostMessage());
            addScopeIfApplicable(scopes, "reactions:read", "reactions:write", manageScopes.getReactionsAccess());
            addScopeIfApplicable(scopes, "read", manageScopes.isReadAccess());
            addScopeIfApplicable(scopes, "reminders:read", "reminders:write", manageScopes.getRemindersAccess());
            addScopeIfApplicable(scopes, "search:read", manageScopes.isSearchAccess());
            addScopeIfApplicable(scopes, "stars:read", "stars:write", manageScopes.getStarsAccess());
            addScopeIfApplicable(scopes, "team:read", manageScopes.isTeamAccess());
            addScopeIfApplicable(scopes, "tokens.basic", manageScopes.isBasicTokenAccess());
            addScopeIfApplicable(scopes, "user.profile:read", "user.profile:write", manageScopes.getUserProfileAccess());
            addScopeIfApplicable(scopes, "users:read.email", manageScopes.isEmailAccess());
            addScopeIfApplicable(scopes, "users:write", manageScopes.isModifyUserProfile());
            addScopeIfApplicable(scopes, "usergroups:read", "usergroups:write", manageScopes.getUserGroupsAccess());

            manageScopes.getManageChannel().ifPresent(manageChannel ->
            {
                addScopeIfApplicable(scopes, "channels:history", manageChannel.isChannelsHistory());
                addScopeIfApplicable(scopes, "channels:read", "channels:write", manageChannel.getChannelsAccess());
            });
            
            manageScopes.getManageGroups().ifPresent(manageGroups ->
            {
                addScopeIfApplicable(scopes, "groups:history", manageGroups.isGroupsHistory());
                addScopeIfApplicable(scopes, "groups:read", "groups:write", manageGroups.getGroupsAccess());
            });

            manageScopes.getManageDirectMessages().ifPresent(manageGroups ->
            {
                addScopeIfApplicable(scopes, "im:history", manageGroups.isDirectMessagesHistory());
                addScopeIfApplicable(scopes, "im:read", "im:write", manageGroups.getDirectMessagesAccess());
            });

            manageScopes.getManageGroupMessages().ifPresent(manageGroups ->
            {
                addScopeIfApplicable(scopes, "mpim:history", manageGroups.isGroupMessagesHistory());
                addScopeIfApplicable(scopes, "mpim:read", "mpim:write", manageGroups.getGroupMessagesAccess());
            });
        });
    }

    private void addScopeIfApplicable(Set<String> scopes, String readScope, String writeScope,
                                      SlackAuthenticatorPluginConfig.Scopes.Access access)
    {
        if (access == SlackAuthenticatorPluginConfig.Scopes.Access.READ)
        {
            scopes.add(readScope);
        }
        else if (access == SlackAuthenticatorPluginConfig.Scopes.Access.WRITE)
        {
            scopes.add(writeScope);
        }
        else
        {
            _logger.error("An unexpected access level was provided.");

            throw new IllegalArgumentException("Cannot process access level");
        }
    }

    @Override
    public Optional<AuthenticationResult> post(Request request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Request preProcess(Request request, Response response)
    {
        return request;
    }
}
