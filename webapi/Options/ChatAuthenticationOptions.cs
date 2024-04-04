// Copyright (c) Microsoft. All rights reserved.

using System.ComponentModel.DataAnnotations;

namespace CopilotChat.WebApi.Options;

/// <summary>
/// Configuration options for authenticating to the service.
/// </summary>
public class ChatAuthenticationOptions
{
    public const string PropertyName = "Authentication";

    public enum AuthenticationType
    {
        None,
        AzureAd,
        Identity
    }

    /// <summary>
    /// Type of authentication.
    /// </summary>
    [Required]
    public AuthenticationType Type { get; set; } = AuthenticationType.Identity;

    /// <summary>
    /// When <see cref="Type"/> is <see cref="AuthenticationType.AzureAd"/>, these are the Azure AD options to use.
    /// </summary>
    [RequiredOnPropertyValue(nameof(Type), AuthenticationType.AzureAd)]
    public AzureAdOptions? AzureAd { get; set; }

    [RequiredOnPropertyValue(nameof(Type), AuthenticationType.Identity)]
    public IdentityOptions? Identity { get; set; }

    /// <summary>
    /// Configuration options for Azure Active Directory (AAD) authorization.
    /// </summary>
    public class AzureAdOptions
    {
        /// <summary>
        /// AAD instance url, i.e., https://login.microsoftonline.com
        /// </summary>
        [Required, NotEmptyOrWhitespace]
        public string Instance { get; set; } = string.Empty;

        /// <summary>
        /// Tenant (directory) ID
        /// </summary>
        [Required, NotEmptyOrWhitespace]
        public string TenantId { get; set; } = string.Empty;

        /// <summary>
        /// Application (client) ID
        /// </summary>
        [Required, NotEmptyOrWhitespace]
        public string ClientId { get; set; } = string.Empty;

        /// <summary>
        /// Required scopes.
        /// </summary>
        [Required]
        public string? Scopes { get; set; } = string.Empty;
    }

    public class IdentityOptions
    {
        [Required, NotEmptyOrWhitespace]
        public string ClientId { get; set; } = string.Empty;

        [Required, NotEmptyOrWhitespace]
        public string ClientSecret { get; set; } = string.Empty;

        [Required, NotEmptyOrWhitespace]
        public string BaseUrl { get; set; } = string.Empty;

        public string? Scope { get; set; } = string.Empty;
    }
}
