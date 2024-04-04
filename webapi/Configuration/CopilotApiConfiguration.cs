// Copyright (c) Microsoft. All rights reserved.

namespace CopilotChat.WebApi.Configuration;

public class CopilotApiConfiguration
{
    public string ApiName { get; set; }

    public string ApiVersion { get; set; }

    public string IdentityServerBaseUrl { get; set; }

    public string ApiBaseUrl { get; set; }

    public string OidcSwaggerUIClientId { get; set; }

    public bool RequireHttpsMetadata { get; set; }

    public string OidcApiName { get; set; }

    public string AdministrationRole { get; set; }

    public string ManagerRole { get; set; }
    public string LocalManagerRole { get; set; }

    public string DoctorRole { get; set; }

    public bool CorsAllowAnyOrigin { get; set; }

    public string[] CorsAllowOrigins { get; set; }
}
