﻿// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.AspNetCore.Http;
using Microsoft.Identity.Web;

namespace CopilotChat.WebApi.Auth;

/// <summary>
/// Class which provides validated security information for use in controllers.
/// </summary>
public class AuthInfo : IAuthInfo
{
    private record struct AuthData(
        string UserId,
        string UserName);

    private readonly Lazy<AuthData> _data;

    public AuthInfo(IHttpContextAccessor httpContextAccessor)
    {
        this._data = new Lazy<AuthData>(() =>
        {
            var user = httpContextAccessor.HttpContext?.User;
            if (user is not null)
            {
                var userIdClaim = user.FindFirst(ClaimConstants.Oid)
                    ?? user.FindFirst(ClaimConstants.ObjectId)
                    ?? user.FindFirst(ClaimConstants.Sub)
                    ?? user.FindFirst(ClaimConstants.NameIdentifierId);
                if (userIdClaim is not null)
                {
                    var tenantIdClaim = user.FindFirst(ClaimConstants.Tid)
                        ?? user.FindFirst(ClaimConstants.TenantId);
                    var userNameClaim = user.FindFirst(ClaimConstants.Name);
                    if (userNameClaim is not null)
                    {
                        return new AuthData
                        {
                            UserId = (tenantIdClaim is null) ? userIdClaim.Value : string.Join(".", userIdClaim.Value, tenantIdClaim.Value),
                            UserName = userNameClaim.Value,
                        };
                    }
                }

            }

            return new AuthData
            {
                UserId = string.Empty,
                UserName = string.Empty,
            };

        }, isThreadSafe: false);
    }

    /// <summary>
    /// The authenticated user's unique ID.
    /// </summary>
    public string UserId => this._data.Value.UserId;

    /// <summary>
    /// The authenticated user's name.
    /// </summary>
    public string Name => this._data.Value.UserName;

}
