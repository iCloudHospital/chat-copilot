// Copyright (c) Jan Škoruba. All Rights Reserved.
// Licensed under the Apache License, Version 2.0.

namespace CopilotChat.WebApi.Configuration;
public class AuthorizationConsts
{
    public const string AdministrationPolicy = "RequireAdministratorRole";
    public const string ManagerPolicy = "RequireManagerRole";
    public const string LocalManagerPolicy = "RequireLocalManagerRole";
    public const string DoctorPolicy = "RequireDoctorRole";

}
