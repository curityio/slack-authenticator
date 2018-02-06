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

    private void handleScopes(Set<String> scopes)
    {
        //add default scope to get user profile info
        scopes.add("users:read");

        _config.getScope().isAdministerWorkspace().ifPresent(admin -> {
            if (admin)
            {
                scopes.add("admin");
            }
        });
        _config.getScope().isManageScopes().ifPresent(manageScopes -> {
            manageScopes.getManageChannel().ifPresent(manageChannel -> {
                if (manageChannel.isChannelsHistory())
                {
                    scopes.add("channels:history");
                }
                switch (manageChannel.getChannelsAccess())
                {
                    case READ:
                        scopes.add("channels:read");
                        break;
                    case WRITE:
                        scopes.add("channels:write");
                }
            });

            if (manageScopes.isChatWriteBotAccess())
            {
                scopes.add("chat:write:bot");
            }
            if (manageScopes.isChatWriteUserAccess())
            {
                scopes.add("chat:write:user");
            }
            if (manageScopes.isClientAccess())
            {
                scopes.add("client");
            }
            if (manageScopes.isCommandsAccess())
            {
                scopes.add("commands");
            }
            switch (manageScopes.getDoNotDisturbAccess())
            {
                case READ:
                    scopes.add("dnd:read");
                    break;
                case WRITE:
                    scopes.add("dnd:write");
            }
            if (manageScopes.isEmojiAccess())
            {
                scopes.add("emoji:read");
            }
            switch (manageScopes.getFilesAccess())
            {
                case READ:
                    scopes.add("files:read");
                    break;
                case WRITE:
                    scopes.add("files:write");
            }
            manageScopes.getManageGroups().ifPresent(manageGroups -> {
                if (manageGroups.isGroupsHistory())
                {
                    scopes.add("groups:history");
                }
                switch (manageGroups.getGroupsAccess())
                {
                    case READ:
                        scopes.add("groups:read");
                        break;
                    case WRITE:
                        scopes.add("groups:write");
                }
            });
            if (manageScopes.isIdentityAccess())
            {
                scopes.add("identity");
            }
            if (manageScopes.isViewAvatar())
            {
                scopes.add("identity.avatar");
            }
            if (manageScopes.isViewEmail())
            {
                scopes.add("identity.email");
            }
            if (manageScopes.isViewTeam())
            {
                scopes.add("identity.team");
            }
            manageScopes.getManageDirectMessages().ifPresent(manageGroups -> {
                if (manageGroups.isDirectMessagesHistory())
                {
                    scopes.add("im:history");
                }
                switch (manageGroups.getDirectMessagesAccess())
                {
                    case READ:
                        scopes.add("im:read");
                        break;
                    case WRITE:
                        scopes.add("im:write");
                }
            });
            if (manageScopes.isCreateWebhook())
            {
                scopes.add("incoming-webhook");
            }
            switch (manageScopes.getLinksAccess())
            {
                case READ:
                    scopes.add("links:read");
                    break;
                case WRITE:
                    scopes.add("links:write");
            }
            manageScopes.getManageGroupMessages().ifPresent(manageGroups -> {
                if (manageGroups.isGroupMessagesHistory())
                {
                    scopes.add("mpim:history");
                }
                switch (manageGroups.getGroupMessagesAccess())
                {
                    case READ:
                        scopes.add("mpim:read");
                        break;
                    case WRITE:
                        scopes.add("mpim:write");
                }
            });
            switch (manageScopes.getPinsAccess())
            {
                case READ:
                    scopes.add("pins:read");
                    break;
                case WRITE:
                    scopes.add("pins:write");
            }
            if (manageScopes.isPostMessage())
            {
                scopes.add("post");
            }
            switch (manageScopes.getReactionsAccess())
            {
                case READ:
                    scopes.add("reactions:read");
                    break;
                case WRITE:
                    scopes.add("reactions:write");
            }
            if (manageScopes.isReadAccess())
            {
                scopes.add("read");
            }
            switch (manageScopes.getRemindersAccess())
            {
                case READ:
                    scopes.add("reminders:read");
                    break;
                case WRITE:
                    scopes.add("reminders:write");
            }
            if (manageScopes.isSearchAccess())
            {
                scopes.add("search:read");
            }
            switch (manageScopes.getStarsAccess())
            {
                case READ:
                    scopes.add("stars:read");
                    break;
                case WRITE:
                    scopes.add("stars:write");
            }
            if (manageScopes.isTeamAccess())
            {
                scopes.add("team:read");
            }
            if (manageScopes.isBasicTokenAccess())
            {
                scopes.add("tokens.basic");
            }
            switch (manageScopes.getUserGroupsAccess())
            {
                case READ:
                    scopes.add("usergroups:read");
                    break;
                case WRITE:
                    scopes.add("usergroups:write");
            }
            switch (manageScopes.getUserProfileAccess())
            {
                case READ:
                    scopes.add("user.profile:read");
                    break;
                case WRITE:
                    scopes.add("user.profile:write");
            }
            if (manageScopes.isEmailAccess())
            {
                scopes.add("users:read.email");
            }
            if (manageScopes.isModifyUserProfile())
            {
                scopes.add("users:write");
            }
        });

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
