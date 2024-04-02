// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using CopilotChat.WebApi.Models.Response;
using CopilotChat.WebApi.Models.Storage;
using Microsoft.SemanticKernel.ChatCompletion;

namespace CopilotChat.WebApi.Models;

public class ichMessageHandler
{
    private string _systemInstructions = string.Empty;
    public string systemInstructions
    {
        get
        {
            return !string.IsNullOrWhiteSpace(this._systemInstructions) ? this._systemInstructions : "This is a chat between an intelligent AI bot named Copilot and one or more participants. SK stands for Semantic Kernel, the AI platform used to build the bot. The AI was trained on data through 2021 and is not aware of events that have occurred since then. It also has no ability to access data on the Internet, so it should not claim that it can or say that it will go and look things up. Try to be concise with your answers, though it is not required. Knowledge cutoff: Saturday, January 1, 2022 / Current date: Tuesday, 02 April 2024 14:00.\n\nEither return [silence] or provide a response to the last message. ONLY PROVIDE A RESPONSE IF the last message WAS ADDRESSED TO THE 'BOT' OR 'COPILOT'. If it appears the last message was not for you, send [silence] as the bot response.";
        }
        set
        {
            this._systemInstructions = value;
        }
    }

    private string _audience = string.Empty;
    public string audience
    {
        get
        {
            return !string.IsNullOrWhiteSpace(this._audience) ? this._audience : "List of participants: Participants:";
        }
        set
        {
            this._audience = value;
        }
    }
    private string _userIntent = string.Empty;
    public string userIntent
    {
        get
        {
            return !string.IsNullOrWhiteSpace(this._userIntent) ? this._userIntent : $"User intent: [{DateTime.Now.DayOfWeek}, {DateTime.Now}]: The user greeted the AI.";
        }
        set
        {
            this._userIntent = value;
        }
    }
    public string allowedChatHistory { get; set; } = string.Empty;

    public string memoryText { get; set; } = string.Empty;

    public int maxRequestTokenBudget { get; set; } = 3052;
    public int tokensUsed { get; set; } = 234;
    public int chatMemoryTokenBudget { get; set; } = 1675;

    public ChatHistory metaPrompt { get; set; } = new ChatHistory();

    public IDictionary<string, CitationSource>? citationMap { get; set; } = null;

    public ichMessageHandler()
    {
        this.citationMap = new Dictionary<string, CitationSource>();
    }

    public void setAllowedChatHistory(string userMent)
    {
        if (!string.IsNullOrWhiteSpace(userMent))
        {
            this.allowedChatHistory = $"Chat history:\n[{DateTime.Now.AddMinutes(-1)}] Bot said: Hello, thank you for democratizing AI's productivity benefits with open source! How can I help you today?\n[{DateTime.Now}]  said: {userMent}";
        }
        else
        {
            this.allowedChatHistory = $"Chat history:\n[{DateTime.Now.AddMinutes(-1)}] Bot said: Hello, thank you for democratizing AI's productivity benefits with open source! How can I help you today?\n[{DateTime.Now}]  said: hi";
        }
    }

    public BotResponsePrompt CreatePrompt()
    {
        return new BotResponsePrompt(this.systemInstructions, this.audience, this.userIntent, this.memoryText, this.allowedChatHistory, this.metaPrompt);
    }
}
