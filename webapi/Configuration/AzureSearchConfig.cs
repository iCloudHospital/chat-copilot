namespace CopilotChat.WebApi.Configuration;

public class AzureSearchConfig
{
    public string SearchServiceName { get; set; } = string.Empty;

    public string SearchServiceQueryApiKey { get; set; } = string.Empty;

    public string Stage { get; set; } = string.Empty;

    public string IndexName { get; set; } = string.Empty;

    public AzureSearchConfig()
    {
    }
}
