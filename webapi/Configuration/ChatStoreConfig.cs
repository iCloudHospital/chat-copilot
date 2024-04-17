namespace CopilotChat.WebApi.Configuration;

public class ChatStoreConfig
{
    public string Type { get; set; } = string.Empty;

    public ChatStoreFilesystem Filesystem { get; set; } = new ChatStoreFilesystem();

    public ChatStoreCosmos Cosmos { get; set; } = new ChatStoreCosmos();

    public ChatStoreConfig()
    {
    }
}

public class ChatStoreFilesystem
{
    public string FilePath { get; set; } = string.Empty;

    public ChatStoreFilesystem()
    {
    }
}

public class ChatStoreCosmos
{
    public string Database { get; set; } = string.Empty;
    public string ChatSessionsContainer { get; set; } = string.Empty;
    public string ChatMessagesContainer { get; set; } = string.Empty;
    public string ChatMemorySourcesContainer { get; set; } = string.Empty;
    public string ChatParticipantsContainer { get; set; } = string.Empty;
    public string ConnectionString { get; set; } = string.Empty;

    public ChatStoreCosmos()
    {
    }
}
