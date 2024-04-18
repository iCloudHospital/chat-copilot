// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Azure;
using Azure.Search.Documents;
using Azure.Search.Documents.Indexes;
using Azure.Search.Documents.Models;
using CopilotChat.WebApi.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.KernelMemory;
using Microsoft.SemanticKernel;
using Newtonsoft.Json;

namespace CopilotChat.WebApi.Search;

public class SearchConnector : ISearchConnector
{
    private readonly AzureSearchConfig _searchConfig;
    private readonly KernelMemoryConfig _memoriesStoreOptions;
    private readonly ILogger _logger;
    private KernelContext _context;

    private readonly Uri serviceEndpoint;
    private readonly AzureKeyCredential credential;
    private readonly SearchIndexClient indexClient;

    private const string SpecialtyIndex = "idx-specialties-int";
    private const string HospitalIndex = "idx-hospitals-int";


    protected SearchOptions? searchOptions;

    public SearchConnector(AzureSearchConfig searchConfig, IOptions<KernelMemoryConfig> memoriesStoreOptions, ILogger<SearchConnector> logger)
    {
        this._searchConfig = searchConfig;
        this._memoriesStoreOptions = memoriesStoreOptions.Value;
        this._logger = logger;

        this.serviceEndpoint = new Uri($"https://{this._searchConfig.SearchServiceName}.search.windows.net/");
        this.credential = new AzureKeyCredential(this._searchConfig.SearchServiceQueryApiKey);
        this.indexClient = new SearchIndexClient(this.serviceEndpoint, this.credential);
    }

    public void SetContext(KernelContext context)
    {
        this._context = context;
    }

    public async Task<List<string>> SpecialtySearchAsync(string query)
    {
        this._logger.LogDebug("Request search query: {0}", query);

        var result = new List<string>();

        if (this._searchConfig != null
            && !string.IsNullOrWhiteSpace(this._searchConfig.SearchServiceName)
            && !string.IsNullOrWhiteSpace(this._searchConfig.SearchServiceQueryApiKey))
        {

            var searchOptions = new SearchOptions()
            {
                IncludeTotalCount = false,
                Size = 3,
                Select = { "Id" },
                Filter = "",
                SearchFields = { "en/Name" },
                OrderBy = { "" }
            };

            var srchclient = this.indexClient.GetSearchClient(SpecialtyIndex);
            var documents = await srchclient.SearchAsync<SearchDocument>($"{query}", searchOptions, this._context.CancellationToken);

            foreach (var doc in documents.Value.GetResults().Take(5))
            {
                result.Add((string)doc.Document["Id"]);
            }
        }

        return result;
    }

    private string CreateFilter(List<string> SpecialtyIds)
    {
        //( HospitalSpecialties/any(hospitalSpecialty: hospitalSpecialty/Specialty/Id eq '<firstId>' or hospitalSpecialty/Specialty/Id eq '<secondId>')) 
        var builder = new StringBuilder(200);
        if (SpecialtyIds != null && SpecialtyIds.Count > 0)
        {
            builder.Append("(HospitalSpecialties/any(hs:");
            int num = 0;
            foreach (string id in SpecialtyIds)
            {
                if (num > 0)
                {
                    builder.Append(" or");
                }

                builder.Append($" hs/Specialty/Id eq '{id}'");

                num++;
            }
            builder.Append("))");
        }
        return builder.ToString();
    }

    public async Task<List<HospitalData>> HospitalSearchAsync(string query, List<string> SpecialtyIds)
    {
        var result = new List<HospitalData>();
        

        if (this._searchConfig != null
            && !string.IsNullOrWhiteSpace(this._searchConfig.SearchServiceName)
            && !string.IsNullOrWhiteSpace(this._searchConfig.SearchServiceQueryApiKey))
        {
            var stopwatch = new Stopwatch();

            var searchOptions = new SearchOptions()
            {
                IncludeTotalCount = false,
                Size = 3,
                Select = { "Id" },
                SearchFields = { "HospitalSpecialties/en/Name" },
                Filter = this.CreateFilter(SpecialtyIds),
                OrderBy = { "" }
            };

            stopwatch.Start();

            var srchclient = this.indexClient.GetSearchClient(HospitalIndex);

            this._logger.LogDebug($"GetSearchClient ElapsedMilliseconds : {stopwatch.ElapsedMilliseconds}");

            var documents = await srchclient.SearchAsync<SearchDocument>(query, searchOptions, this._context.CancellationToken);

            this._logger.LogDebug($"SearchAsync ElapsedMilliseconds : {stopwatch.ElapsedMilliseconds}");

            this._logger.LogDebug("HospitalSerach Query : ");
            this._logger.LogDebug(JsonConvert.SerializeObject(searchOptions));

            foreach (var doc in documents.Value.GetResults().Take(3))
            {
                string id = (string)doc.Document["Id"];

                this._logger.LogDebug($"result id : {id}");

                //string hospitalId = (string)doc.Document["HospitalId"];
                //string sourceEntityId = (string)doc.Document["SourceEntityId"];
                //string sourceEntityName = (string)doc.Document["SourceEntityName"];
                //string slug = (string)doc.Document["Slug_en"];
                //string content = (string)doc.Document["Content_en"];
                //string sourcePage = (string)doc.Document["SourcePage"];
                //content = content.Replace('\r', ' ').Replace('\n', ' ');

                //sb.AppendLine($"{sourcePage}: {content}");
                result.Add(new HospitalData() { Id = id, Name = "" });
            }

            this._logger.LogDebug($"GetResults ElapsedMilliseconds : {stopwatch.ElapsedMilliseconds}");

            stopwatch.Stop();
        }

        return result;
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
