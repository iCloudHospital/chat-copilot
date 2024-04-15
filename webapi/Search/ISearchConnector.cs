// Copyright (c) Microsoft. All rights reserved.

using System.Threading.Tasks;

namespace CopilotChat.WebApi.Search;

/// <summary>
/// Search connector interface.
/// </summary>
public interface ISearchConnector
{
    /// <summary>
    /// Search with given query.
    /// </summary>
    /// <param name="indexName"></param>
    /// <param name="query"></param>
    /// <param name="context"></param>
    /// <returns></returns>
    Task<string> SearchAsync(string indexName, string query);

    void SetContext(KernelContext context);
}
