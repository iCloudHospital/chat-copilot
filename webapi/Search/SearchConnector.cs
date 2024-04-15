// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Azure;
using Azure.Search.Documents;
using Azure.Search.Documents.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.KernelMemory;
using Microsoft.SemanticKernel;

namespace CopilotChat.WebApi.Search;

public class SearchConnector : ISearchConnector
{
    private readonly KernelMemoryConfig _memoriesStoreOptions;
    private readonly ILogger _logger;
    private KernelContext _context;

    public SearchConnector(IOptions<KernelMemoryConfig> memoriesStoreOptions, ILogger<SearchConnector> logger)
    {
        this._memoriesStoreOptions = memoriesStoreOptions.Value;
        this._logger = logger;
    }

    public void SetContext(KernelContext context)
    {
        this._context = context;
    }

    public async Task<string> SearchAsync(string indexName, string query)
    {
        this._logger.LogDebug("Request search query: {0}", query);

        var searchClient = this.CreateSearchClient(indexName);

        var searchOptions = this.CreateSearchOptions(this._context.Variables);

        var sb = new StringBuilder();

        // apply conditional url depends on stage int or prd
        var documents = await searchClient.SearchAsync<SearchDocument>($"{query}", searchOptions, this._context.CancellationToken);

        foreach (var doc in documents.Value.GetResults())
        {
            string id = (string)doc.Document["Id"];
            string hospitalId = (string)doc.Document["HospitalId"];
            string sourceEntityId = (string)doc.Document["SourceEntityId"];
            string sourceEntityName = (string)doc.Document["SourceEntityName"];
            string slug = (string)doc.Document["Slug_en"];
            string content = (string)doc.Document["Content_en"];
            string sourcePage = (string)doc.Document["SourcePage"];
            content = content.Replace('\r', ' ').Replace('\n', ' ');

            sb.AppendLine($"{sourcePage}: {content}");
        }
        return sb.ToString();

    }

    private SearchClient CreateSearchClient(string indexName)
    {
        var config = new Dictionary<string, object>();

        if (this._memoriesStoreOptions.IsUseAzureAISearch(this._context.GetConfiguration))
        {
            var azureSearchConfig = this._memoriesStoreOptions.GetAzureAISearch(this._context.GetConfiguration);
            var endPoint = new Uri(uriString: azureSearchConfig.Endpoint);
            var credential = new AzureKeyCredential(azureSearchConfig.APIKey);
            var client = new SearchClient(endPoint, indexName, credential);
            this._logger.LogDebug("SearchClient created with indexName: {0}", indexName);
            return client;
        }

        this._logger.LogError("AzureAISearch apiKey or endPoint is empty in appsettings.json");
        throw new Exception("AzureAISearch apiKey or endPoint is empty in appsettings.json");
    }

    private SearchOptions CreateSearchOptions(KernelArguments context)
    {
        //var defaultFilter = "(Translations/any(translation: translation/LanguageCode eq 'en' and translation/IsConfirmed eq true))";
        var defaultFilter = "";

        if (context["hospitalId"] != null)
        {
            var hospitalId = context["hospitalId"] ?? string.Empty;
            defaultFilter += $"{(string.IsNullOrEmpty(defaultFilter) ? "" : " and")}" + $"HospitalId eq '{hospitalId}'";
        };

        return new SearchOptions
        {
            //QueryType = SearchQueryType.Semantic,
            //QueryLanguage = "en",
            Filter = defaultFilter,
            Select = {

                "Id",
                "HospitalId",
                "SourceEntityId",
                "SourceEntityName",
                "Slug_en",
                "Content_en",
                "SourcePage",
                "Slug_en"
            },
            IncludeTotalCount = true,
            Size = 3,
            SearchFields = { "Content_en" },
            HighlightFields = { "Content_en" },
            HighlightPreTag = "<b>",
            HighlightPostTag = "</b>"
        };
    }
}
