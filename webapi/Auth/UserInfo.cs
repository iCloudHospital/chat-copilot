using Microsoft.SemanticKernel;
using System.ComponentModel;

namespace CopilotChat.WebApi.Auth;

public class UserInfo
{
    private readonly IAuthInfo _authInfo;

    private readonly HospitalInfo _hospitalInfo;

    public bool IsLoggedIn { get; set; } = false;

    public UserInfo(IAuthInfo authInfo, HospitalInfo hospital)
    {
        this._authInfo = authInfo;
        this._hospitalInfo = hospital;

        if (this._authInfo != null && !string.IsNullOrWhiteSpace(this._authInfo!.UserId))
        {
            this.IsLoggedIn = true;
        }
    }

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
        return this.IsLoggedIn ? this._authInfo.Name : "required login";
    }

    [KernelFunction]
    [Description("Required login")]
    public string RequiredLogin()
    {
        string link = string.Empty;
        if (this.IsLoggedIn)
        {
            link = "Already your login.";
        }
        else
        {
            link = "<a href=\"https://localhost:5001/Account/Login\" target=\"_blank\">Login Page</a>";
        }

        return link;
    }

    [KernelFunction]
    [Description("Gets the logout")]
    public string RequiredLogout()
    {
        string link = string.Empty;
        if (this.IsLoggedIn)
        {
            link = "<a href=\"https://localhost:5001/Account/logout\" target=\"_blank\">Logout Page</a>";
        }
        else
        {
            link = "Already yoiur logout.";
        }

        return link;
    }

#pragma warning restore CA1024 // Use properties where appropriate
}
