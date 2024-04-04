using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;
using System.Threading.Tasks;
using CopilotChat.WebApi.Auth;
using CopilotChat.WebApi.Hubs;
using CopilotChat.WebApi.Models;
using CopilotChat.WebApi.Models.Request;
using CopilotChat.WebApi.Models.Response;
using CopilotChat.WebApi.Models.Storage;
using CopilotChat.WebApi.Options;
using CopilotChat.WebApi.Plugins.Chat;
using CopilotChat.WebApi.Services;
using CopilotChat.WebApi.Storage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using Microsoft.SemanticKernel.Connectors.OpenAI;

namespace CopilotChat.WebApi.Controllers;

[ApiExplorerSettings(IgnoreApi=true)]
[AllowAnonymous]
[ApiController]
[Route("test")]
public class SingleChatController : ControllerBase, IDisposable
{
    private readonly ILogger<SingleChatController> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly List<IDisposable> _disposables;
    private readonly ITelemetryService _telemetryService;
    private readonly ServiceOptions _serviceOptions;
    private readonly IDictionary<string, Plugin> _plugins;
    private readonly IHttpContextAccessor _httpContextAccessor;

    private const string ChatPluginName = nameof(ChatPlugin);
    private const string ChatFunctionName = "Chat";
    private const string GeneratingResponseClientCall = "ReceiveBotResponseStatus";

    public SingleChatController(
        ILogger<SingleChatController> logger,
        IHttpClientFactory httpClientFactory,
        ITelemetryService telemetryService,
        IOptions<ServiceOptions> serviceOptions,
        IHttpContextAccessor httpContextAccessor,
        IDictionary<string, Plugin> plugins)
    {
        this._logger = logger;
        this._httpClientFactory = httpClientFactory;
        this._telemetryService = telemetryService;
        this._disposables = new List<IDisposable>();
        this._serviceOptions = serviceOptions.Value;
        this._httpContextAccessor = httpContextAccessor;
        this._plugins = plugins;
    }

    [Route("chats/{chatId:guid}/messages")]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status504GatewayTimeout)]
    public async Task<IActionResult> SingleChatAsync(
        [FromServices] IHubContext<MessageRelayHub> messageRelayHubContext,
        [FromServices] ChatSessionRepository chatSessionRepository,
        [FromServices] ChatParticipantRepository chatParticipantRepository,
        [FromServices] IAuthInfo authInfo,
        [FromBody] Ask ask,
        [FromRoute] Guid chatId)
    {
        string chatIdString = chatId.ToString();
        var contextVariables = GetContextVariables(ask, authInfo, chatIdString);

        var builder = Kernel.CreateBuilder();
        builder.AddAzureOpenAIChatCompletion("gpt-35-turbo", //gpt-35-turbo
              "https://chopenaiservice.openai.azure.com/",
              "91d7d187370c42c5bab250869460097c"
              );
        builder.Plugins.AddFromType<UserInfo>();
        var kernel = builder.Build();

        ChatHistory history = new ChatHistory();//this.GetObjectFromSession();
        
        history.AddSystemMessage(@"You're a virtual assistant that helps people find information.");

        var chatCompletionService = kernel.GetRequiredService<IChatCompletionService>();

        string combinedResponse = string.Empty;

        history.AddUserMessage(ask.Input);

        OpenAIPromptExecutionSettings openAIPromptExecutionSettings = new()
        {
            MaxTokens = 200,
            ToolCallBehavior = ToolCallBehavior.AutoInvokeKernelFunctions
        };

        //await messageRelayHubContext.Clients.Group(chatIdString).SendAsync("ReceiveBotResponseStatus", chatIdString, "processing...", null);

        var prompt = new BotResponsePrompt("", "", "", "", "", history);

        var chatMessage = CopilotChatMessage.CreateBotResponseMessage(chatIdString, string.Empty, JsonSerializer.Serialize(prompt), null, null);
        await messageRelayHubContext.Clients.Group(chatIdString).SendAsync("ReceiveMessage", chatIdString, "", chatMessage, null);

        var response = chatCompletionService.GetStreamingChatMessageContentsAsync(
                       history,
                       executionSettings: openAIPromptExecutionSettings,
                       kernel: kernel);

        await foreach (var message in response)
        {
            combinedResponse += message;
        }

        //contextVariables["Input"] = combinedResponse;
        history.AddAssistantMessage(combinedResponse);

        AskResult chatAskResult = new()
        {
            Value = combinedResponse,
            Variables = contextVariables.Select(v => new KeyValuePair<string, object?>(v.Key, v.Value))
        };

        chatMessage.Content = combinedResponse;

        await messageRelayHubContext.Clients.Group(chatIdString).SendAsync("ReceiveMessageUpdate", chatMessage);
        await messageRelayHubContext.Clients.Group(chatIdString).SendAsync(GeneratingResponseClientCall, chatIdString, "", chatAskResult.Value);

        return this.Ok(chatAskResult);
    }

    private void SaveObjectToSession(ChatHistory obj)
    {
        var formatter = new BinaryFormatter();
        using (var stream = new MemoryStream())
        {
            formatter.Serialize(stream, obj);
            this._httpContextAccessor.HttpContext.Session.Set("ChatHistory", stream.ToArray());
        }
    }

    private ChatHistory GetObjectFromSession()
    {
        var data = this._httpContextAccessor.HttpContext.Session.Get("ChatHistory");
        if (data != null)
        {
            var formatter = new BinaryFormatter();
            using (var stream = new MemoryStream(data))
            {
                return (ChatHistory)formatter.Deserialize(stream);
            }
        }
        return new ChatHistory();
    }

    private static KernelArguments GetContextVariables(Ask ask, IAuthInfo authInfo, string chatId)
    {
        const string UserIdKey = "userId";
        const string UserNameKey = "userName";
        const string ChatIdKey = "chatId";
        const string MessageKey = "message";

        var contextVariables = new KernelArguments();
        foreach (var variable in ask.Variables)
        {
            contextVariables[variable.Key] = variable.Value;
        }

        contextVariables[UserIdKey] = authInfo.UserId;
        contextVariables[UserNameKey] = authInfo.Name;
        contextVariables[ChatIdKey] = chatId;
        contextVariables[MessageKey] = ask.Input;

        return contextVariables;
    }

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

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        this.Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}

