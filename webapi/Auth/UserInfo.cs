// Copyright (c) Microsoft. All rights reserved.

using Microsoft.SemanticKernel;
using System.ComponentModel;

namespace CopilotChat.WebApi.Auth;

public class UserInfo
{
    public bool IsLoggedIn { get; set; } = false;

#pragma warning disable CA1024 // Use properties where appropriate
    [KernelFunction]
    [Description("Gets the state of the light.")]
    public string GetState()
    {
        return this.IsLoggedIn ? "on" : "off";
    }
#pragma warning restore CA1024 // Use properties where appropriate

    [KernelFunction]
    [Description("Changes the state of the light.'")]
    public string ChangeState(bool newState)
    {
        this.IsLoggedIn = newState;
        var state = this.GetState();

        return state;
    }
}
