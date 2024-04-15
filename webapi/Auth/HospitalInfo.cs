// Copyright (c) Microsoft. All rights reserved.

namespace CopilotChat.WebApi.Auth;

public class HospitalInfo
{
    public string Id { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public HospitalInfo()
    {
    }

    public HospitalInfo(string id)
    {
        this.Id = id;
    }
}
