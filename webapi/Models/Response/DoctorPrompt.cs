// Copyright (c) Microsoft. All rights reserved.

using System.Text.Json.Serialization;

namespace CopilotChat.WebApi.Models.Response;

public class DoctorPrompt
{
    [JsonPropertyName("userPersona")]
    public string UserPersona { get; set; } = string.Empty;

    [JsonPropertyName("context")]
    public string Context { get; set; } = string.Empty;

    [JsonPropertyName("userSymptoms")]
    public string UserSymptoms { get; set; } = string.Empty;

    [JsonPropertyName("pastInteractions")]
    public string PastInteractions { get; set; } = string.Empty;

    [JsonPropertyName("interactionHistory")]
    public string InteractionHistory { get; set; } = string.Empty;

    public DoctorPrompt(
        string userPersona,
        string context,
        string userSymptoms,
        string pastInteractions,
        string interactionHistory
    )
    {
        this.UserPersona = userPersona;
        this.Context = context;
        this.UserSymptoms = this.ExtractSymptoms(userSymptoms);
        this.PastInteractions = pastInteractions;
        this.InteractionHistory = interactionHistory;
    }

    private string ExtractSymptoms(string userAction)
    {
        return "";
    }
}
