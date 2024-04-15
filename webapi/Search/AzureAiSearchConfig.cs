// Copyright (c) Microsoft. All rights reserved.

using Microsoft.Extensions.Configuration;
using Microsoft.KernelMemory;
using System.Collections.Generic;

namespace CopilotChat.WebApi.Search;

public class AzureAiSearchConfig
{
    public string APIKey { get; set; } = string.Empty;

    public string Endpoint { get; set; } = string.Empty;

    public AzureAiSearchConfig()
    {
    }
}

public static class ExtendAzureAiSearchConfig
{
    public static string GetAzureAiSearchKey(this IConfiguration configuration)
    {
        return configuration["KernelMemory:Services:AzureAISearch:APIKey"] ?? string.Empty;
    }

    public static bool IsUseAzureAISearch(this KernelMemoryConfig kernelconfig, IConfiguration configuration)
    {
        var config = new Dictionary<string, object>();

        if (kernelconfig != null
            && kernelconfig.Services != null
            && kernelconfig.Services.TryGetValue("AzureAISearch", out config))
        {
            if (config.ContainsKey("Endpoint"))
            {
                try
                {
                    string endpoint = (config["Endpoint"] != null) ? config["Endpoint"].ToString() : string.Empty;
                    string apikey = configuration.GetAzureAiSearchKey();

                    if (!string.IsNullOrWhiteSpace(endpoint) && !string.IsNullOrWhiteSpace(apikey))
                    {
                        return true;
                    }
                }
                catch
                {
                    return false;
                }
            }
        }

        return false;
    }

    public static AzureAiSearchConfig GetAzureAISearch(this KernelMemoryConfig kernelconfig, IConfiguration configuration)
    {
        var config = new Dictionary<string, object>();
        var aaconfig = new AzureAiSearchConfig();

        if (kernelconfig != null
            && kernelconfig.Services != null
            && kernelconfig.Services.TryGetValue("AzureAISearch", out config))
        {
            if (config.ContainsKey("Endpoint"))
            {
                try
                {
                    aaconfig.Endpoint = (config["Endpoint"] != null) ? config["Endpoint"].ToString() : string.Empty;
                    aaconfig.APIKey = configuration.GetAzureAiSearchKey();
                }
                catch
                {
                }
            }
        }

        return aaconfig;
    }
}
