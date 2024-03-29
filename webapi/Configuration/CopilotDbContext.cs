// Copyright (c) Microsoft. All rights reserved.

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CopilotChat.WebApi.Configuration;

public class CopilotDbContext : IdentityDbContext<UserIdentity, IdentityRole, string, CopilotUserClaim, CopilotUserRole, CopilotUserLogin, CopilotIdentityRole, CopilotUserToken>
{
    public CopilotDbContext(DbContextOptions<CopilotDbContext> options) : base(options)
    {

    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }
}

public class CopilotUserClaim : IdentityUserClaim<string>
{

}

public class CopilotUserRole : IdentityUserRole<string>
{

}

public class CopilotUserLogin : IdentityUserLogin<string>
{

}

public class CopilotIdentityRole : IdentityRoleClaim<string>
{

}

public class CopilotUserToken : IdentityUserToken<string>
{

}

public class UserIdentity : IdentityUser
{

}

