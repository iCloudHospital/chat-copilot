// Copyright (c) Microsoft. All rights reserved.

using System.Collections.Generic;
using System.Threading.Tasks;

namespace CopilotChat.WebApi.Search;

public interface ISearchConnector
{
    Task<List<string>> SpecialtySearchAsync(string query);

    Task<List<HospitalData>> HospitalSearchAsync(string query, List<string> SpecialtyIds);

    void SetContext(KernelContext context);
}
