using System.ComponentModel;
using Microsoft.SemanticKernel;

namespace CopilotChat.WebApi.Search;

public class SearchPlugin
{
    private readonly string _source;

    public SearchPlugin(string source)
    {
        this._source = source;
    }

#pragma warning disable CA1024 // Use properties where appropriate

    [KernelFunction]
    [Description("Gets hospital search infomation.")]
    public string GetSearch()
    {
        return (!string.IsNullOrWhiteSpace(this._source)) ? this._source : "sorry, not found result.";
    }

#pragma warning restore CA1024 // Use properties where appropriate
}
