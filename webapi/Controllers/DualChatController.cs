using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
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
using CopilotChat.WebApi.Plugins.Utils;
using CopilotChat.WebApi.Search;
using CopilotChat.WebApi.Services;
using CopilotChat.WebApi.Storage;
using CopilotChat.WebApi.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.KernelMemory;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.Plugins.OpenApi;
using Newtonsoft.Json;
using static CopilotChat.WebApi.Models.Storage.CopilotChatMessage;

namespace CopilotChat.WebApi.Controllers;

/// <summary>
/// Controller responsible for handling chat messages and responses.
/// </summary>
[AllowAnonymous]
[ApiController]
public class DualChatController : ControllerBase, IDisposable
{
    private readonly ILogger<DualChatController> _logger;
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
    private readonly ChatSessionRepository _sessionRepository;
    private readonly PromptsOptions _promptOptions;
    private readonly ChatMessageRepository _messageRepository;
    private readonly ChatParticipantRepository _participantRepository;

    private const string ChatPluginName = nameof(ChatPlugin);
    private const string ChatFunctionName = "Chat";
    private const string GeneratingResponseClientCall = "ReceiveBotResponseStatus";

    public DualChatController(
        ILogger<DualChatController> logger,
        IHttpClientFactory httpClientFactory,
        ITelemetryService telemetryService,
        IOptions<ServiceOptions> serviceOptions,
        CopilotApiConfiguration copliotApiConfiguration,
        AzureSearchConfig searchConfig,
        ChatStoreConfig cosmos,
        ChatSessionRepository sessionRepository,
        ChatMessageRepository messageRepository,
        ChatParticipantRepository participantRepository,
        IOptions<KernelMemoryConfig> memoryOptions,
        IOptions<PromptsOptions> promptsOptions,
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
        this._sessionRepository = sessionRepository;
        this._copliotApiConfiguration = copliotApiConfiguration;
        this._cosmos = cosmos;
        this._plugins = plugins;
        this._promptOptions = promptsOptions.Value;
        this.Configuration = configuration;
        this._messageRepository = messageRepository;
        this._participantRepository = participantRepository;
        this._searchConnector = searchConnector;
        this.memoryOptions = memoryOptions.Value;
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
    [Route("dual/chats/messages")]
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
        [FromBody] Ask ask)
    {
        this._logger.LogDebug("New Chat message received.");

        //2채널 대화를 하기 위해 정보를 담아둘 클래스 생성
        var data = new DualChatData(authInfo);
        data.originQuery = ask.Input;  //원본 질문을 담아놓습니다.

        if (this._searchConfig != null && !string.IsNullOrWhiteSpace(this._searchConfig.SearchServiceName))
        {
            //Azure AI Search 관련 환경 변수들이 셋팅되어 있다면, IsAzureSearch값을 true 설정합니다.
            data.IsAzureSearch = true;
        }

        ChatSession? userSession = null;
        ChatSession? ichSession = null;
        var SpentTimes = new Dictionary<string, long>();
        var SpentTokens = new Dictionary<string, long>();

        var stopwatch = new Stopwatch();

        //채널 세션의 기본 설명문장 (큰 의미없음)
        string description = "This is CloudHospital's chatbot service for receiving medical consultations through intelligent AI chatbot.";

        if (!(await chatSessionRepository.TryFindByIdAsync(data.userChatID, callback: c => userSession = c)))
        {
            stopwatch.Start();

            userSession = ChatSession.CreateSession(data.userChatID, data.userChatID, description);
            await this._sessionRepository.CreateAsync(userSession);

            var chatMessage = CopilotChatMessage.CreateBotResponseMessage(
                data.userChatID,
                this._promptOptions.InitialBotMessage,
                string.Empty, // The initial bot message doesn't need a prompt.
                null,
                TokenUtils.EmptyTokenUsages());
            await this._messageRepository.CreateAsync(chatMessage);

            // Add the user to the chat session
            await this._participantRepository.CreateAsync(new ChatParticipant(authInfo.UserId, data.userChatID));

            stopwatch.Stop();

            SpentTimes.Add("Session Create Time", stopwatch.ElapsedMilliseconds);
        }

        if (data.IsAzureSearch)
        {
            //Azure AI Search가 활성화 되어 있다면, 2채널 대화를 위해 System Session을 생성합니다.
            if (!(await chatSessionRepository.TryFindByIdAsync(data.systemChatID, callback: c => ichSession = c)))
            {
                ichSession = ChatSession.CreateSession(data.systemChatID, data.systemChatID, description);
                await this._sessionRepository.CreateAsync(ichSession);
                await this._participantRepository.CreateAsync(new ChatParticipant(authInfo.UserId, data.systemChatID));
            }
        }

        var response = new ServiceInfoResponse()
        {
            MemoryStore = new MemoryStoreInfoResponse()
            {
                Types = Enum.GetNames(typeof(MemoryStoreType)),
                SelectedType = this.memoryOptions.GetMemoryStoreType(this.Configuration).ToString(),
            }
        };

        var openApiPluginAuthHeaders = this.GetPluginAuthHeaders(this.HttpContext.Request.Headers);

        data.userArgs = GetContextVariables(data.UserAsk(ask), authInfo, data.userChatID, ask.Input);
        if (data.IsAzureSearch)
        {
            //시스템 대화용 Context를 생성합니다.
            data.systemArgs = GetContextVariables(data.SystemAsk(ask), authInfo, data.systemChatID, data.SymptomPrompt());
        }

        stopwatch.Reset();
        stopwatch.Start();

        await this.RegisterFunctionsAsync(kernel, openApiPluginAuthHeaders, data.userArgs, authInfo);
        await this.RegisterHostedFunctionsAsync(kernel, userSession!.EnabledPlugins);

        using CancellationTokenSource? cts = this._serviceOptions.TimeoutLimitInS is not null
            ? new CancellationTokenSource(TimeSpan.FromSeconds((double)this._serviceOptions.TimeoutLimitInS))
            : null;

        KernelFunction? chatFunction = kernel.Plugins.GetFunction(ChatPluginName, ChatFunctionName);

        stopwatch.Stop();

        SpentTimes.Add("Function Create Time", stopwatch.ElapsedMilliseconds);

        FunctionResult? result = null;

        bool IsHospital = false;  //우리가 답변할 내용인지 판단값
        string Symptom = string.Empty; //증상명

        if (data.IsAzureSearch)
        {
            stopwatch.Reset();
            stopwatch.Start();

            //먼저 질문자의 질문이 병원진료, 증상 등과 관련있는 질문인지 확인합니다.
            result = await kernel.InvokeAsync(chatFunction!, data.systemArgs, cts?.Token ?? default);

            stopwatch.Stop();
            SpentTimes.Add("First Query for Azure Search", stopwatch.ElapsedMilliseconds);
            SpentTokens.Add("First Query for Azure Search", data.GetTokenCheck(data.systemArgs));

            if (data.IsSymptom())
            {
                stopwatch.Reset();
                stopwatch.Start();

                //병원진료와 관련있는 질문인 경우, 해당 질문에서 증상 관련 키워드를 추출합니다.
                data.systemArgs = GetContextVariables(data.SystemAsk(ask), authInfo, data.systemChatID, data.SearchPrompt());
                result = await kernel.InvokeAsync(chatFunction!, data.systemArgs, cts?.Token ?? default);

                stopwatch.Stop();
                SpentTimes.Add("Second Query for Azure Search", stopwatch.ElapsedMilliseconds);
                SpentTokens.Add("Second Query for Azure Search", data.GetTokenCheck(data.systemArgs));

                Symptom = data.ChatMessage;
                if (!string.IsNullOrWhiteSpace(Symptom))
                {
                    IsHospital = true;

                    stopwatch.Reset();
                    stopwatch.Start();

                    //증상관련 키워드를 정상적으로 추출했다면, Azure AI Search를 이용해서 Specialty/Id를 확인합니다.
                    var kernelContext = new KernelContext(data.systemArgs, cts, response, this.Configuration);
                    this._searchConnector.SetContext(kernelContext);
                    var specialtyIds = await this._searchConnector.SpecialtySearchAsync(Symptom);

                    stopwatch.Stop();
                    SpentTimes.Add("Azure Search SpecialtyId", stopwatch.ElapsedMilliseconds);

                    if (specialtyIds != null && specialtyIds.Count > 0)
                    {
                        stopwatch.Reset();
                        stopwatch.Start();

                        //Specialty/Id가 확인이 되었다면, 이제 병원정보를 검색합니다.
                        data.hospitals = await this._searchConnector.HospitalSearchAsync(Symptom, specialtyIds);
                        if (data.hospitals != null && data.hospitals.Count > 0)
                        {
                            //검색된 병원정보가 존재하면, IsResult를 true로 변경해 줍니다.
                            data.IsResult = true;
                        }

                        stopwatch.Stop();
                        SpentTimes.Add("Azure Search Hospital", stopwatch.ElapsedMilliseconds);
                    }
                }
            }
        }
        string msg = string.Empty;

        if (IsHospital)
        {
            var userMessage = new CopilotChatMessage(authInfo.UserId, authInfo.Name, data.userChatID, data.originQuery, string.Empty, null, AuthorRoles.User, ChatMessageType.Message, TokenUtils.EmptyTokenUsages());
            await this._messageRepository.CreateAsync(userMessage);

            if (data.IsResult && data.hospitals != null && data.hospitals.Count > 0)
            {
                var builder = new StringBuilder(200);
                builder.AppendLine("Recommend the following hospitals.");
                builder.Append(data.ApiMessage);
                msg = builder.ToString();
                //만약 병원정보가 검색된게 있다면, 사용자 질문에 대한 답변을 병원정보로 치환해 줍니다.
                data.userArgs["input"] = msg;
                await this.RegisterSearchResult(kernel, data.ApiMessage);
                //ChatBot이 사용자에게 한 대답은 병원정보로 대답해준 것으로 History 정보를 변경해 둡니다.
                //await this.UpdateContentByChatIdAndUserIdAsync(data.userChatID, "Bot", data.ApiMessage);

                var chatMessage = CopilotChatMessage.CreateBotResponseMessage(
                    data.userChatID,
                    msg,
                    string.Empty, // The initial bot message doesn't need a prompt.
                    null,
                    TokenUtils.EmptyTokenUsages());
                await this._messageRepository.CreateAsync(chatMessage);
            }
            else
            {
                //이 단계로 진입했다는 건, 증상 키워드는 추출했으나, 해당 증상에 맞는 Specialty/Id를 찾지 못했다는 의미.
                //또는 적절한 병원을 찾지 못했다는 의미
                msg = "Couldn't find the hospital for your symptoms, please visit the nearest hospital in your area.";

                var chatMessage = CopilotChatMessage.CreateBotResponseMessage(
                    data.userChatID,
                    msg,
                    string.Empty, // The initial bot message doesn't need a prompt.
                    null,
                    TokenUtils.EmptyTokenUsages());
                await this._messageRepository.CreateAsync(chatMessage);

                data.userArgs["input"] = msg;
            }
        }
        else
        {
            stopwatch.Reset();
            stopwatch.Start();

            result = await kernel.InvokeAsync(chatFunction!, data.userArgs, cts?.Token ?? default);

            stopwatch.Stop();
            SpentTimes.Add("User Query Response", stopwatch.ElapsedMilliseconds);
            SpentTokens.Add("User Query Response", data.GetTokenCheck(data.userArgs));
        }

        await this.UpdateContentByChatIdAndUserIdAsync(data.userChatID, authInfo.UserId, data.originQuery);
        this._telemetryService.TrackPluginFunction(ChatPluginName, ChatFunctionName, true);

        //AskResult chatAskResult = new()
        //{
        //    Value = result.ToString() ?? string.Empty,
        //    Variables = data.userArgs.Select(v => new KeyValuePair<string, object?>(v.Key, v.Value))
        //};

        var chatAskResult = data.GetAskResult(SpentTimes, SpentTokens);
        if (IsHospital)
        {
            chatAskResult.Message = msg;
        }

        await messageRelayHubContext.Clients.Group(data.userChatID).SendAsync(GeneratingResponseClientCall, data.userChatID, "", (result.ToString() ?? string.Empty));

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

    private async Task RegisterFunctionsAsync(Kernel kernel, Dictionary<string, string> authHeaders, KernelArguments variables, IAuthInfo authInfo)
    {
        var tasks = new List<Task>();

        tasks.Add(this.RegisterUserinfo(kernel, authInfo));

        await Task.WhenAll(tasks);
    }

    private async Task RegisterUserinfo(Kernel kernel, IAuthInfo authInfo)
    {
        this._logger.LogInformation("Enabling UserInfo plugin.");
        var user = new UserInfo(authInfo, new HospitalInfo());
        await Task.Factory.StartNew(() => kernel.Plugins.AddFromObject(user), CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
    }

    private async Task RegisterSearchResult(Kernel kernel, string source)
    {
        this._logger.LogInformation("Enabling Search plugin.");
        var sp = new SearchPlugin(source);
        await Task.Factory.StartNew(() => kernel.Plugins.AddFromObject(sp), CancellationToken.None, TaskCreationOptions.None, TaskScheduler.Default);
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

    private static KernelArguments GetContextVariables(Ask ask, IAuthInfo authInfo, string chatId, string input)
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
        contextVariables[MessageKey] = input;

        return contextVariables;
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

public class DualChatData
{
    public string uid = "3E01CA0D-02F1-4EEB-BDAA-8BB529E72E88";
    public string sid = "5DF663DE-6E72-4DCE-9CA2-47C827D7E323";

    public string originQuery { get; set; } = string.Empty;

    public string userChatID
    {
        get
        {
            return this.uid;
        }
    }

    public string systemChatID
    {
        get
        {
            return this.sid;
        }
    }

    public bool IsAzureSearch { get; set; } = false;

    public bool IsResult { get; set; } = false;

    public KernelArguments? userArgs { get; set; }

    public KernelArguments? systemArgs { get; set; }

    public string userId { get; set; } = string.Empty;

    public List<HospitalData> hospitals { get; set; } = new List<HospitalData>();

    public DualChatData(IAuthInfo autoinfo)
    {
        this.userId = autoinfo.UserId;
    }

    public ApiResult GetAskResult(Dictionary<string, long> spend, Dictionary<string, long> tokens)
    {
        var result = new ApiResult();
        result.Query = this.originQuery;
        result.ChatId = this.userChatID;
        result.UserId = this.userId;
        if (this.IsResult && this.hospitals != null && this.hospitals.Count > 0)
        {
            result.MessageType = "Module";
            result.Message = this.ApiMessage;
        }
        else
        {
            result.MessageType = "Text";
            result.Message = this.ChatMessage;
        }
        result.SpentTimes = spend;
        result.SpentToken = tokens;

        return result;
    }

    public string SearchPrompt()
    {
        StringBuilder builder = new StringBuilder(200);
        builder.AppendLine("Extract the words in the sentence within the quotation marks listed below and tell us which words are relevant to the search.");
        builder.AppendLine("Answer the extracted words separated by commas, but do not say anything other than the extracted words.");
        builder.AppendLine("Exclude all unnecessary words, such as adjectives, adverbs, and investigations, except those that are relevant to the search.");
        builder.AppendLine($"\"{this.originQuery.Replace("\"", "")}\"");
        return builder.ToString();
    }

    public string SymptomPrompt()
    {
        StringBuilder builder = new StringBuilder(200);
        builder.AppendLine("Answer true if the question in quotation marks is related to medical care, such as a symptom or pain, or answer false.");
        builder.AppendLine("Do not answer anything other than true or false.");
        builder.AppendLine($"\"{this.originQuery.Replace("\"", "")}\"");
        return builder.ToString();
    }

    public Ask UserAsk(Ask ask)
    {
        string json = JsonConvert.SerializeObject(ask);
        Ask result = JsonConvert.DeserializeObject<Ask>(json);
        result.Variables.Append(new KeyValuePair<string, string>("chatId", this.userChatID));
        return result;
    }

    public Ask SystemAsk(Ask ask)
    {
        string json = JsonConvert.SerializeObject(ask);
        Ask result = JsonConvert.DeserializeObject<Ask>(json);
        result.Variables.Append(new KeyValuePair<string, string>("chatId", this.systemChatID));
        return result;
    }


    public bool IsSymptom()
    {
        bool result = false;

        try
        {
            if (this.systemArgs != null && this.systemArgs.TryGetValue("input", out object? messageObject) && messageObject is string)
            {
                if (messageObject.ToString().Trim().Equals("true", StringComparison.OrdinalIgnoreCase)
                    || string.IsNullOrWhiteSpace(messageObject.ToString().Replace("true", "", StringComparison.OrdinalIgnoreCase)))
                {
                    result = true;
                }
                else if (messageObject.ToString().Trim().Substring(0, 4) == "true")
                {
                    result = true;
                }
            }
        }
        catch
        {
            result = false;
        }

        return result;
    }

    public long GetTokenCheck(KernelArguments? context)
    {
        long result = 0;

        try
        {
            string temp = string.Empty;

            if (context != null && context.TryGetValue("tokenUsage", out object? messageObject) && messageObject is string)
            {
                temp = messageObject.ToString();

                if (!string.IsNullOrWhiteSpace(temp))
                {
                    var tokens = JsonConvert.DeserializeObject<tokenUsage>(temp) ?? new tokenUsage();
                    result = tokens.Sum();
                }
            }
        }
        catch
        {
            result = 0;
        }

        return result;
    }

    public string ChatMessage
    {
        get
        {
            string result = string.Empty;

            try
            {
                if (this.systemArgs != null && this.systemArgs.TryGetValue("input", out object? messageObject) && messageObject is string)
                {
                    result = messageObject.ToString();
                }
            }
            catch
            {
                result = "";
            }

            return result;
        }
    }

    public string ApiMessage
    {
        get
        {
            StringBuilder builder = new StringBuilder(200);

            try
            {
                builder.Append("{ module : \"hospitals\", data [");
                int num = 0;
                foreach(var hospital in this.hospitals)
                {
                    if (num > 0) { builder.Append(","); }
                    builder.Append($"\"{hospital.Id}\"");
                    num++;
                }
                builder.Append("] }");
            }
            catch (Exception ex)
            {
                builder.Clear();
                builder.Append("{ module : \"error\", data [\"" + ex.Message + "\"]");
            }

            return builder.ToString();
        }
    }

    public class tokenUsage
    {
        public int audienceExtraction { get; set; } = 0;
        public int userIntentExtraction { get; set; } = 0;
        public int metaPromptTemplate { get; set; } = 0;
        public int workingMemoryExtraction { get; set; } = 0;
        public int longTermMemoryExtraction { get; set; } = 0;
        public int responseCompletion { get; set; } = 0;

        public tokenUsage()
        {
        }

        public int Sum()
        {
            return (this.audienceExtraction
                    + this.userIntentExtraction
                    + this.metaPromptTemplate
                    + this.workingMemoryExtraction
                    + this.longTermMemoryExtraction
                    + this.responseCompletion);
        }
    }
}
