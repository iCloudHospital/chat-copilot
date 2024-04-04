// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.KernelMemory;
using Microsoft.SemanticKernel;
using Microsoft.Extensions.Http.Resilience;
using System.Threading.Tasks;
using System.Net;
using System.Threading;
using CopilotChat.WebApi.Auth;

namespace CopilotChat.WebApi.Services;

/// <summary>
/// Extension methods for registering Semantic Kernel related services.
/// </summary>
public sealed class SemanticKernelProvider
{
    private readonly IKernelBuilder _builderChat;

    public SemanticKernelProvider(IServiceProvider serviceProvider, IConfiguration configuration, IHttpClientFactory httpClientFactory)
    {
        this._builderChat = InitializeCompletionKernel(serviceProvider, configuration, httpClientFactory);
    }

    /// <summary>
    /// Produce semantic-kernel with only completion services for chat.
    /// </summary>
    public Kernel GetCompletionKernel()
    {
buildStart:
        Thread.Sleep(1000 * 2);
        try
        {
            return this._builderChat.Build();
        }
        catch
        {
            goto buildStart;
        }
    }

    private static IKernelBuilder InitializeCompletionKernel(
        IServiceProvider serviceProvider,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory)
    {
        var builder = Kernel.CreateBuilder();

        builder.Services.AddLogging();
        //builder.Services.ConfigureHttpClientDefaults(c =>
        //{
        //    // Use a standard resiliency policy, augmented to retry on 401 Unauthorized for this example
        //    c.AddStandardResilienceHandler().Configure(o =>
        //    {
        //        o.Retry.ShouldHandle = args => ValueTask.FromResult(args.Outcome.Result?.StatusCode is HttpStatusCode.Unauthorized);
        //    });
        //});
        //builder.Plugins.AddFromType<UserInfo>();

        var memoryOptions = serviceProvider.GetRequiredService<IOptions<KernelMemoryConfig>>().Value;

        switch (memoryOptions.TextGeneratorType)
        {
            case string x when x.Equals("AzureOpenAI", StringComparison.OrdinalIgnoreCase):
            case string y when y.Equals("AzureOpenAIText", StringComparison.OrdinalIgnoreCase):
                var azureAIOptions = memoryOptions.GetServiceConfig<AzureOpenAIConfig>(configuration, "AzureOpenAIText");
#pragma warning disable CA2000 // No need to dispose of HttpClient instances from IHttpClientFactory
                builder.AddAzureOpenAIChatCompletion(
                    "gpt-4",  //azureAIOptions.Deployment
                    azureAIOptions.Endpoint,
                    azureAIOptions.APIKey,
                    serviceId: "hospitalName",
                    httpClient: httpClientFactory.CreateClient()
                    );

                builder.AddAzureOpenAIChatCompletion(
                    "gpt-35-turbo",
                    azureAIOptions.Endpoint,
                    azureAIOptions.APIKey,
                    serviceId: "hospitalName",
                    httpClient: httpClientFactory.CreateClient()
                    );
                break;
                

            case string x when x.Equals("OpenAI", StringComparison.OrdinalIgnoreCase):
                var openAIOptions = memoryOptions.GetServiceConfig<OpenAIConfig>(configuration, "OpenAI");
                builder.AddOpenAIChatCompletion(
                    openAIOptions.TextModel,
                    openAIOptions.APIKey,
                    httpClient: httpClientFactory.CreateClient());
#pragma warning restore CA2000
                break;

            default:
                throw new ArgumentException($"Invalid {nameof(memoryOptions.TextGeneratorType)} value in 'KernelMemory' settings.");
        }

        //custom plugin add
        

        return builder;
    }
}
