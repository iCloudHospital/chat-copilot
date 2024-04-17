// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using CopilotChat.WebApi.Auth;
using CopilotChat.WebApi.Configuration;
using CopilotChat.WebApi.Hubs;
using CopilotChat.WebApi.Models.Request;
using CopilotChat.WebApi.Models.Response;
using CopilotChat.WebApi.Models.Storage;
using CopilotChat.WebApi.Options;
using CopilotChat.WebApi.Plugins.Chat;
using CopilotChat.WebApi.Search;
using CopilotChat.WebApi.Services;
using CopilotChat.WebApi.Storage;
using CopilotChat.WebApi.Utilities;
using DocumentFormat.OpenXml.Bibliography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Graph;
using Microsoft.KernelMemory;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Plugins.MsGraph;
using Microsoft.SemanticKernel.Plugins.MsGraph.Connectors;
using Microsoft.SemanticKernel.Plugins.MsGraph.Connectors.Client;
using Microsoft.SemanticKernel.Plugins.OpenApi;

namespace CopilotChat.WebApi.Controllers;

/// <summary>
/// Controller responsible for handling chat messages and responses.
/// </summary>
[AllowAnonymous]
[ApiController]
public class ChatController : ControllerBase, IDisposable
{
    private readonly ILogger<ChatController> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly List<IDisposable> _disposables;
    private readonly ITelemetryService _telemetryService;
    private readonly ServiceOptions _serviceOptions;
    private readonly IDictionary<string, Plugin> _plugins;
    private readonly CopilotApiConfiguration _copliotApiConfiguration;
    private readonly IConfiguration Configuration;
    private readonly KernelMemoryConfig memoryOptions;
    private readonly ISearchConnector _searchConnector;
    private readonly AzureSearchConfig _searchConfig;
    private readonly ChatStoreConfig _cosmos;

    private const string ChatPluginName = nameof(ChatPlugin);
    private const string ChatFunctionName = "Chat";
    private const string GeneratingResponseClientCall = "ReceiveBotResponseStatus";

    
    public ChatController(
        ILogger<ChatController> logger,
        IHttpClientFactory httpClientFactory,
        ITelemetryService telemetryService,
        IOptions<ServiceOptions> serviceOptions,
        CopilotApiConfiguration copliotApiConfiguration,
        AzureSearchConfig searchConfig,
        ChatStoreConfig cosmos,
        IOptions<KernelMemoryConfig> memoryOptions,
        IConfiguration configuration,
        ISearchConnector searchConnector,
        IDictionary<string, Plugin> plugins)
    {
        this._logger = logger;
        this._httpClientFactory = httpClientFactory;
        this._telemetryService = telemetryService;
        this._disposables = new List<IDisposable>();
        this._searchConfig = searchConfig;
        this._serviceOptions = serviceOptions.Value;
        this._copliotApiConfiguration = copliotApiConfiguration;
        this._cosmos = cosmos;
        this._plugins = plugins;
        this.Configuration = configuration;
        this._searchConnector = searchConnector;
        this.memoryOptions = memoryOptions.Value;
    }

    private string SearchPrompt(string keyword)
    {
        StringBuilder builder = new StringBuilder(200);
        builder.AppendLine("Extract the words in the sentence within the quotation marks listed below and tell us which words are relevant to the search.");
        builder.AppendLine("Answer the extracted words separated by commas, but do not say anything other than the extracted words.");
        builder.AppendLine("Exclude all unnecessary words, such as adjectives, adverbs, and investigations, except those that are relevant to the search.");
        builder.AppendLine($"\"{keyword.Replace("\"", "")}\"");
        return builder.ToString();
    }

    /// <summary>
    /// Invokes the chat function to get a response from the bot.
    /// </summary>
    /// <param name="kernel">Semantic kernel obtained through dependency injection.</param>
    /// <param name="messageRelayHubContext">Message Hub that performs the real time relay service.</param>
    /// <param name="chatSessionRepository">Repository of chat sessions.</param>
    /// <param name="chatParticipantRepository">Repository of chat participants.</param>
    /// <param name="authInfo">Auth info for the current request.</param>
    /// <param name="ask">Prompt along with its parameters.</param>
    /// <param name="chatId">Chat ID.</param>
    /// <returns>Results containing the response from the model.</returns>
    [Route("chats/{chatId:guid}/messages")]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status504GatewayTimeout)]
    [Authorize(Policy = AuthorizationConsts.DoctorPolicy)]
    public async Task<IActionResult> ChatAsync(
        [FromServices] Kernel kernel,
        [FromServices] IHubContext<MessageRelayHub> messageRelayHubContext,
        [FromServices] ChatSessionRepository chatSessionRepository,
        [FromServices] ChatParticipantRepository chatParticipantRepository,
        [FromServices] IAuthInfo authInfo,
        [FromBody] Ask ask,
        [FromRoute] Guid chatId)
    {
        this._logger.LogDebug("Chat message received.");

        var response = new ServiceInfoResponse()
        {
            MemoryStore = new MemoryStoreInfoResponse()
            {
                Types = Enum.GetNames(typeof(MemoryStoreType)),
                SelectedType = this.memoryOptions.GetMemoryStoreType(this.Configuration).ToString(),
            }
        };

        string orignQuery = ask.Input;

        string chatIdString = chatId.ToString();

        // Put ask's variables in the context we will use.
        var contextVariables = GetContextVariables(ask, authInfo, chatIdString, "");

        // Verify that the chat exists and that the user has access to it.
        ChatSession? chat = null;
        if (!(await chatSessionRepository.TryFindByIdAsync(chatIdString, callback: c => chat = c)))
        {
            return this.NotFound("Failed to find chat session for the chatId specified in variables.");
        }

        if (!(await chatParticipantRepository.IsUserInChatAsync(authInfo.UserId, chatIdString)))
        {
            return this.Forbid("User does not have access to the chatId specified in variables.");
        }


        // Register plugins that have been enabled
        var openApiPluginAuthHeaders = this.GetPluginAuthHeaders(this.HttpContext.Request.Headers);
        var hospital = new HospitalInfo("");
        await this.RegisterFunctionsAsync(kernel, openApiPluginAuthHeaders, contextVariables, authInfo, hospital);

        // Register hosted plugins that have been enabled
        await this.RegisterHostedFunctionsAsync(kernel, chat!.EnabledPlugins);

        // Run the function.
        FunctionResult? result = null;

        using CancellationTokenSource? cts = this._serviceOptions.TimeoutLimitInS is not null
            ? new CancellationTokenSource(TimeSpan.FromSeconds((double)this._serviceOptions.TimeoutLimitInS))
            : null;
        try
        {
            KernelFunction? chatFunction = kernel.Plugins.GetFunction(ChatPluginName, ChatFunctionName);

            if (this._searchConfig != null && !string.IsNullOrWhiteSpace(this._searchConfig.SearchServiceName))
            {
                if (contextVariables != null && contextVariables.TryGetValue("message", out object messageObject) && messageObject is string)
                {
                    string msg = contextVariables["message"].ToString();
                    if (!string.IsNullOrWhiteSpace(msg))
                    {
                        string prompt = this.SearchPrompt(msg);
                        contextVariables["message"] = prompt;
                    }
                }
            }

            result = await kernel.InvokeAsync(chatFunction!, contextVariables, cts?.Token ?? default);
            await this.UpdateContentByChatIdAndUserIdAsync(chatIdString, authInfo.UserId, orignQuery);
            this._telemetryService.TrackPluginFunction(ChatPluginName, ChatFunctionName, true);
        }
        catch (Exception ex)
        {
            if (ex is OperationCanceledException || ex.InnerException is OperationCanceledException)
            {
                // Log the timeout and return a 504 response
                this._logger.LogError("The {FunctionName} operation timed out.", ChatFunctionName);
                return this.StatusCode(StatusCodes.Status504GatewayTimeout, $"The chat {ChatFunctionName} timed out.");
            }

            this._telemetryService.TrackPluginFunction(ChatPluginName, ChatFunctionName, false);

            throw;
        }

        if (this._searchConfig != null && !string.IsNullOrWhiteSpace(this._searchConfig.SearchServiceName))
        {
            if (contextVariables != null && contextVariables.TryGetValue("input", out object messageObject) && messageObject is string)
            {
                string msg = contextVariables["input"].ToString();
                if (!string.IsNullOrWhiteSpace(msg))
                {
                    var kernelContext = new KernelContext(contextVariables, cts, response, this.Configuration);
                    this._searchConnector.SetContext(kernelContext);
                    var specialtyIds = await this._searchConnector.SpecialtySearchAsync(msg);
                    if (specialtyIds != null && specialtyIds.Count > 0)
                    {
                        var hospitals = await this._searchConnector.HospitalSearchAsync(msg, specialtyIds);
                        if (hospitals != null && hospitals.Count > 0)
                        {
                            string source = String.Join(",", (from h in hospitals select h.Id));

                            if (!string.IsNullOrWhiteSpace(source))
                            {
                                contextVariables["input"] = $"hospitals : {source}";
                                contextVariables["message"] = orignQuery;
                                await this.RegisterSearchResult(kernel, source);
                                await this.UpdateContentByChatIdAndUserIdAsync(chatIdString, "Bot", $"hospitals : {source}");
                            }
                        }
                    }
                }
            }
        }

        AskResult chatAskResult = new()
        {
            Value = result.ToString() ?? string.Empty,
            Variables = contextVariables.Select(v => new KeyValuePair<string, object?>(v.Key, v.Value))
        };

        // Broadcast AskResult to all users
        await messageRelayHubContext.Clients.Group(chatIdString).SendAsync(GeneratingResponseClientCall, chatIdString, "", chatAskResult.Value);

        return this.Ok(chatAskResult);
    }

    [Route("chats/{chatId:guid}/{hospitalid:guid}/messages")]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status504GatewayTimeout)]
    [Authorize(Policy = AuthorizationConsts.DoctorPolicy)]
    public async Task<IActionResult> ChatAsync(
    [FromServices] Kernel kernel,
    [FromServices] IHubContext<MessageRelayHub> messageRelayHubContext,
    [FromServices] ChatSessionRepository chatSessionRepository,
    [FromServices] ChatParticipantRepository chatParticipantRepository,
    [FromServices] IAuthInfo authInfo,
    [FromBody] Ask ask,
    [FromRoute] Guid chatId,
    [FromRoute] Guid hospitalid)
    {
        this._logger.LogDebug("Chat message received.");

        string chatIdString = chatId.ToString();
        string hospitalIdString = hospitalid.ToString();

        // Put ask's variables in the context we will use.
        var contextVariables = GetContextVariables(ask, authInfo, chatIdString, hospitalIdString);

        // Verify that the chat exists and that the user has access to it.
        ChatSession? chat = null;
        if (!(await chatSessionRepository.TryFindByIdAsync(chatIdString, callback: c => chat = c)))
        {
            return this.NotFound("Failed to find chat session for the chatId specified in variables.");
        }

        if (!(await chatParticipantRepository.IsUserInChatAsync(authInfo.UserId, chatIdString)))
        {
            return this.Forbid("User does not have access to the chatId specified in variables.");
        }

        if (chat != null)
        {
            chat.HospitalID = hospitalIdString;
        }

        // Register plugins that have been enabled
        var openApiPluginAuthHeaders = this.GetPluginAuthHeaders(this.HttpContext.Request.Headers);
        var hospital = new HospitalInfo(hospitalIdString);
        await this.RegisterFunctionsAsync(kernel, openApiPluginAuthHeaders, contextVariables, authInfo, hospital);

        // Register hosted plugins that have been enabled
        await this.RegisterHostedFunctionsAsync(kernel, chat!.EnabledPlugins);

        // Get the function to invoke
        KernelFunction? chatFunction = kernel.Plugins.GetFunction(ChatPluginName, ChatFunctionName);

        // Run the function.
        FunctionResult? result = null;

        try
        {
            using CancellationTokenSource? cts = this._serviceOptions.TimeoutLimitInS is not null
                // Create a cancellation token source with the timeout if specified
                ? new CancellationTokenSource(TimeSpan.FromSeconds((double)this._serviceOptions.TimeoutLimitInS))
                : null;

            result = await kernel.InvokeAsync(chatFunction!, contextVariables, cts?.Token ?? default);
            this._telemetryService.TrackPluginFunction(ChatPluginName, ChatFunctionName, true);
        }
        catch (Exception ex)
        {
            if (ex is OperationCanceledException || ex.InnerException is OperationCanceledException)
            {
                // Log the timeout and return a 504 response
                this._logger.LogError("The {FunctionName} operation timed out.", ChatFunctionName);
                return this.StatusCode(StatusCodes.Status504GatewayTimeout, $"The chat {ChatFunctionName} timed out.");
            }

            this._telemetryService.TrackPluginFunction(ChatPluginName, ChatFunctionName, false);

            throw;
        }

        AskResult chatAskResult = new()
        {
            Value = result.ToString() ?? string.Empty,
            Variables = contextVariables.Select(v => new KeyValuePair<string, object?>(v.Key, v.Value))
        };

        // Broadcast AskResult to all users
        await messageRelayHubContext.Clients.Group(chatIdString).SendAsync(GeneratingResponseClientCall, chatIdString, "", chatAskResult.Value);

        return this.Ok(chatAskResult);
    }

    /// <summary>
    /// Parse plugin auth values from request headers.
    /// </summary>
    private Dictionary<string, string> GetPluginAuthHeaders(IHeaderDictionary headers)
    {
        // Create a regex to match the headers
        var regex = new Regex("x-sk-copilot-(.*)-auth", RegexOptions.IgnoreCase);

        // Create a dictionary to store the matched headers and values
        var authHeaders = new Dictionary<string, string>();

        // Loop through the request headers and add the matched ones to the dictionary
        foreach (var header in headers)
        {
            var match = regex.Match(header.Key);
            if (match.Success)
            {
                // Use the first capture group as the key and the header value as the value
                authHeaders.Add(match.Groups[1].Value.ToUpperInvariant(), header.Value!);
            }
        }

        return authHeaders;
    }


    private async Task UpdateContentByChatIdAndUserIdAsync(string chatId, string userId, string newContent)
    {
        using (var _cosmosClient = new CosmosClient(this._cosmos.Cosmos.ConnectionString))
        {
            var _database = _cosmosClient.GetDatabase(this._cosmos.Cosmos.Database);
            var _container = _database.GetContainer(this._cosmos.Cosmos.ChatMessagesContainer);
            var queryText = "SELECT TOP 1 * FROM c WHERE c.chatId = @chatId AND c.userId = @userId ORDER BY c.timestamp DESC";
            var queryDefinition = new QueryDefinition(queryText)
                                      .WithParameter("@chatId", chatId)
                                      .WithParameter("@userId", userId);
            var iterator = _container.GetItemQueryIterator<dynamic>(queryDefinition);
            var recentRecord = (await iterator.ReadNextAsync()).FirstOrDefault();
            if (recentRecord != null)
            {
                recentRecord.content = newContent;
                var partitionKey = new PartitionKey(recentRecord.partition.ToString());
                await _container.ReplaceItemAsync(recentRecord, recentRecord.id.ToString(), partitionKey);
            }
        }
    }


    /// <summary>
    /// Register functions with the kernel.
    /// </summary>
    private async Task RegisterFunctionsAsync(Kernel kernel, Dictionary<string, string> authHeaders, KernelArguments variables, IAuthInfo authInfo, HospitalInfo hospital)
    {
        // Register authenticated functions with the kernel only if the request includes an auth header for the plugin.

        var tasks = new List<Task>();

        // GitHub
        if (authHeaders.TryGetValue("GITHUB", out string? GithubAuthHeader))
        {
            tasks.Add(this.RegisterGithubPlugin(kernel, GithubAuthHeader));
        }

        // Jira
        if (authHeaders.TryGetValue("JIRA", out string? JiraAuthHeader))
        {
            tasks.Add(this.RegisterJiraPlugin(kernel, JiraAuthHeader, variables));
        }

        // Microsoft Graph
        if (authHeaders.TryGetValue("GRAPH", out string? GraphAuthHeader))
        {
            tasks.Add(this.RegisterMicrosoftGraphPlugins(kernel, GraphAuthHeader));
        }

        if (variables.TryGetValue("customPlugins", out object? customPluginsString))
        {
            tasks.AddRange(this.RegisterCustomPlugins(kernel, customPluginsString, authHeaders));
        }

        tasks.Add(this.RegisterUserinfo(kernel, authInfo, hospital));

        await Task.WhenAll(tasks);
    }

    private async Task RegisterGithubPlugin(Kernel kernel, string GithubAuthHeader)
    {
        this._logger.LogInformation("Enabling GitHub plugin.");
        BearerAuthenticationProvider authenticationProvider = new(() => Task.FromResult(GithubAuthHeader));
        await kernel.ImportPluginFromOpenApiAsync(
            pluginName: "GitHubPlugin",
            filePath: GetPluginFullPath("GitHubPlugin/openapi.json"),
            new OpenApiFunctionExecutionParameters
            {
                AuthCallback = authenticationProvider.AuthenticateRequestAsync,
            });
    }

    private async Task RegisterUserinfo(Kernel kernel, IAuthInfo authInfo, HospitalInfo hospital)
    {
        this._logger.LogInformation("Enabling UserInfo plugin.");
        var user = new UserInfo(authInfo, hospital);
        await Task.Factory.StartNew(() => kernel.Plugins.AddFromObject(user), CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
        //await Task.Factory.StartNew(() => kernel.Plugins.AddFromType<UserInfo>(), CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
    }

    private async Task RegisterSearchResult(Kernel kernel, string source)
    {
        this._logger.LogInformation("Enabling Search plugin.");
        var sp = new SearchPlugin(source);
        await Task.Factory.StartNew(() => kernel.Plugins.AddFromObject(sp), CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
        //await Task.Factory.StartNew(() => kernel.Plugins.AddFromType<UserInfo>(), CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
    }

    private async Task RegisterJiraPlugin(Kernel kernel, string JiraAuthHeader, KernelArguments variables)
    {
        this._logger.LogInformation("Registering Jira plugin");
        var authenticationProvider = new BasicAuthenticationProvider(() => { return Task.FromResult(JiraAuthHeader); });
        var hasServerUrlOverride = variables.TryGetValue("jira-server-url", out object? serverUrlOverride);

        await kernel.ImportPluginFromOpenApiAsync(
            pluginName: "JiraPlugin",
            filePath: GetPluginFullPath("OpenApi/JiraPlugin/openapi.json"),
            new OpenApiFunctionExecutionParameters
            {
                AuthCallback = authenticationProvider.AuthenticateRequestAsync,
                ServerUrlOverride = hasServerUrlOverride ? new Uri(serverUrlOverride!.ToString()!) : null,
            });
    }

    private Task RegisterMicrosoftGraphPlugins(Kernel kernel, string GraphAuthHeader)
    {
        this._logger.LogInformation("Enabling Microsoft Graph plugin(s).");
        BearerAuthenticationProvider authenticationProvider = new(() => Task.FromResult(GraphAuthHeader));
        GraphServiceClient graphServiceClient = this.CreateGraphServiceClient(authenticationProvider.GraphClientAuthenticateRequestAsync);

        kernel.ImportPluginFromObject(new TaskListPlugin(new MicrosoftToDoConnector(graphServiceClient)), "todo");
        kernel.ImportPluginFromObject(new CalendarPlugin(new OutlookCalendarConnector(graphServiceClient)), "calendar");
        kernel.ImportPluginFromObject(new EmailPlugin(new OutlookMailConnector(graphServiceClient)), "email");
        return Task.CompletedTask;
    }

    private IEnumerable<Task> RegisterCustomPlugins(Kernel kernel, object? customPluginsString, Dictionary<string, string> authHeaders)
    {
        CustomPlugin[]? customPlugins = JsonSerializer.Deserialize<CustomPlugin[]>(customPluginsString!.ToString()!);

        if (customPlugins != null)
        {
            foreach (CustomPlugin plugin in customPlugins)
            {
                if (authHeaders.TryGetValue(plugin.AuthHeaderTag.ToUpperInvariant(), out string? PluginAuthValue))
                {
                    // Register the ChatGPT plugin with the kernel.
                    this._logger.LogInformation("Enabling {0} plugin.", plugin.NameForHuman);

                    // TODO: [Issue #44] Support other forms of auth. Currently, we only support user PAT or no auth.
                    var requiresAuth = !plugin.AuthType.Equals("none", StringComparison.OrdinalIgnoreCase);
                    Task authCallback(HttpRequestMessage request, string _, OpenAIAuthenticationConfig __, CancellationToken ___ = default)
                    {
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", PluginAuthValue);

                        return Task.CompletedTask;
                    }

                    yield return kernel.ImportPluginFromOpenAIAsync(
                        $"{plugin.NameForModel}Plugin",
                        PluginUtils.GetPluginManifestUri(plugin.ManifestDomain),
                        new OpenAIFunctionExecutionParameters
                        {
                            HttpClient = this._httpClientFactory.CreateClient(),
                            IgnoreNonCompliantErrors = true,
                            AuthCallback = requiresAuth ? authCallback : null
                        });
                }
            }
        }
        else
        {
            this._logger.LogDebug("Failed to deserialize custom plugin details: {0}", customPluginsString);
        }
    }

    /// <summary>
    /// Create a Microsoft Graph service client.
    /// </summary>
    /// <param name="authenticateRequestAsyncDelegate">The delegate to authenticate the request.</param>
    private GraphServiceClient CreateGraphServiceClient(AuthenticateRequestAsyncDelegate authenticateRequestAsyncDelegate)
    {
        MsGraphClientLoggingHandler graphLoggingHandler = new(this._logger);
        this._disposables.Add(graphLoggingHandler);

        IList<DelegatingHandler> graphMiddlewareHandlers =
            GraphClientFactory.CreateDefaultHandlers(new DelegateAuthenticationProvider(authenticateRequestAsyncDelegate));
        graphMiddlewareHandlers.Add(graphLoggingHandler);

        HttpClient graphHttpClient = GraphClientFactory.Create(graphMiddlewareHandlers);
        this._disposables.Add(graphHttpClient);

        GraphServiceClient graphServiceClient = new(graphHttpClient);
        return graphServiceClient;
    }

    private async Task RegisterHostedFunctionsAsync(Kernel kernel, HashSet<string> enabledPlugins)
    {
        foreach (string enabledPlugin in enabledPlugins)
        {
            if (this._plugins.TryGetValue(enabledPlugin, out Plugin? plugin))
            {
                this._logger.LogDebug("Enabling hosted plugin {0}.", plugin.Name);

                Task authCallback(HttpRequestMessage request, string _, OpenAIAuthenticationConfig __, CancellationToken ___ = default)
                {
                    request.Headers.Add("X-Functions-Key", plugin.Key);

                    return Task.CompletedTask;
                }

                // Register the ChatGPT plugin with the kernel.
                await kernel.ImportPluginFromOpenAIAsync(
                    PluginUtils.SanitizePluginName(plugin.Name),
                    PluginUtils.GetPluginManifestUri(plugin.ManifestDomain),
                    new OpenAIFunctionExecutionParameters
                    {
                        HttpClient = this._httpClientFactory.CreateClient(),
                        IgnoreNonCompliantErrors = true,
                        AuthCallback = authCallback
                    });
            }
            else
            {
                this._logger.LogWarning("Failed to find plugin {0}.", enabledPlugin);
            }
        }

        return;
    }

    private static KernelArguments GetContextVariables(Ask ask, IAuthInfo authInfo, string chatId, string hospitalId)
    {
        const string UserIdKey = "userId";
        const string UserNameKey = "userName";
        const string ChatIdKey = "chatId";
        const string MessageKey = "message";
        const string HospitalId = "hospitalId";

        var contextVariables = new KernelArguments();
        foreach (var variable in ask.Variables)
        {
            contextVariables[variable.Key] = variable.Value;
        }

        contextVariables[UserIdKey] = authInfo.UserId;
        contextVariables[UserNameKey] = authInfo.Name;
        contextVariables[ChatIdKey] = chatId;
        contextVariables[MessageKey] = ask.Input;
        contextVariables[HospitalId] = hospitalId;

        return contextVariables;
    }

    private static string GetPluginFullPath(string pluginPath)
    {
        return Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "Plugins", pluginPath);
    }

    /// <summary>
    /// Dispose of the object.
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (IDisposable disposable in this._disposables)
            {
                disposable.Dispose();
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        this.Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Retrieves authentication content (e.g. username/password, API key) via the provided delegate and
/// applies it to HTTP requests using the "basic" authentication scheme.
/// </summary>
public class BasicAuthenticationProvider
{
    private readonly Func<Task<string>> _credentialsDelegate;

    /// <summary>
    /// Creates an instance of the <see cref="BasicAuthenticationProvider"/> class.
    /// </summary>
    /// <param name="credentialsDelegate">Delegate for retrieving credentials.</param>
    public BasicAuthenticationProvider(Func<Task<string>> credentialsDelegate)
    {
        this._credentialsDelegate = credentialsDelegate;
    }

    /// <summary>
    /// Applies the authentication content to the provided HTTP request message.
    /// </summary>
    /// <param name="request">The HTTP request message.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async Task AuthenticateRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
    {
        // Base64 encode
        string encodedContent = Convert.ToBase64String(Encoding.UTF8.GetBytes(await this._credentialsDelegate().ConfigureAwait(false)));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", encodedContent);
    }
}

/// <summary>
/// Retrieves a token via the provided delegate and applies it to HTTP requests using the
/// "bearer" authentication scheme.
/// </summary>
public class BearerAuthenticationProvider
{
    private readonly Func<Task<string>> _bearerTokenDelegate;

    /// <summary>
    /// Creates an instance of the <see cref="BearerAuthenticationProvider"/> class.
    /// </summary>
    /// <param name="bearerTokenDelegate">Delegate to retrieve the bearer token.</param>
    public BearerAuthenticationProvider(Func<Task<string>> bearerTokenDelegate)
    {
        this._bearerTokenDelegate = bearerTokenDelegate;
    }

    /// <summary>
    /// Applies the token to the provided HTTP request message.
    /// </summary>
    /// <param name="request">The HTTP request message.</param>
    public async Task AuthenticateRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
    {
        var token = await this._bearerTokenDelegate().ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>
    /// Applies the token to the provided HTTP request message.
    /// </summary>
    /// <param name="request">The HTTP request message.</param>
    public async Task GraphClientAuthenticateRequestAsync(HttpRequestMessage request)
    {
        await this.AuthenticateRequestAsync(request);
    }

    /// <summary>
    /// Applies the token to the provided HTTP request message.
    /// </summary>
    /// <param name="request">The HTTP request message.</param>
    public async Task OpenAIAuthenticateRequestAsync(HttpRequestMessage request, string pluginName, OpenAIAuthenticationConfig openAIAuthConfig, CancellationToken cancellationToken = default)
    {
        await this.AuthenticateRequestAsync(request, cancellationToken);
    }


}
