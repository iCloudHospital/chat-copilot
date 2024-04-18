// Copyright (c) Microsoft. All rights reserved.

using System.Collections.Generic;

namespace CopilotChat.WebApi.Models.Response;

public class ApiResult
{
    public string Query { get; set; } = string.Empty;

    public string Message { get; set; } = string.Empty;

    public string ChatId { get; set; } = string.Empty;

    public string UserId { get; set; } = string.Empty;

    public string MessageType { get; set; } = string.Empty;

    public Dictionary<string, long> SpentTimes { get; set; } = new Dictionary<string, long>();

    public Dictionary<string, long> SpentToken{ get; set; } = new Dictionary<string, long>();

    public ApiResult()
    {
    }
}
