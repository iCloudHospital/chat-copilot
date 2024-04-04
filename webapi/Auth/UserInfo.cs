using Microsoft.SemanticKernel;
using System.ComponentModel;

namespace CopilotChat.WebApi.Auth;

public class UserInfo
{
    public UserInfo()
    {
        this.IsLoggedIn = true;
    }

    public bool IsLoggedIn { get; set; } = false;

#pragma warning disable CA1024 // Use properties where appropriate
    [KernelFunction]
    [Description("Gets the my current status of the login.")]
    public string GetState()
    {
        return this.IsLoggedIn ? "login" : "logout";
    }

    [KernelFunction]
    [Description("Gets the my name of the login.")]
    public string GetName()
    {
        return this.IsLoggedIn ? "parkheesung" : "required login";
    }
#pragma warning restore CA1024 // Use properties where appropriate

    [KernelFunction]
    [Description("Gets the login or logout.'")]
    public string ChangeState(bool newState)
    {
        string link = string.Empty;
        if (this.IsLoggedIn)
        {
            link = "https://localhost:5001/logout";
        }
        else
        {
            link = "https://localhost:5001";
        }

        return link;
    }
}
