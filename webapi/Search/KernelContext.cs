using System.Threading;
using CopilotChat.WebApi.Models.Response;
using Microsoft.Extensions.Configuration;
using Microsoft.SemanticKernel;

namespace CopilotChat.WebApi.Search;

public class KernelContext
{
    private KernelArguments _contextVariables;
    private CancellationTokenSource? _cts;
    private ServiceInfoResponse _response;
    private IConfiguration _configuration;

    public KernelContext(KernelArguments contextVariables, CancellationTokenSource? cts, ServiceInfoResponse response, IConfiguration config)
    {
        this._contextVariables = contextVariables;
        this._cts = cts;
        this._response = response;
        this._configuration = config;
    }

    public IConfiguration GetConfiguration
    {
        get
        {
            return this._configuration;
        }
    }

    public KernelArguments Variables
    {
        get
        {
            return (this._contextVariables != null) ? this._contextVariables : new KernelArguments();
        }
    }

    public CancellationToken CancellationToken
    {
        get
        {
            return (this._cts != null) ? this._cts.Token : CancellationToken.None;
        }
    }
}
