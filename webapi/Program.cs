using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using CopilotChat.WebApi.Configuration;
using CopilotChat.WebApi.Configuration.Authorization;
using CopilotChat.WebApi.Extensions;
using CopilotChat.WebApi.Hubs;
using CopilotChat.WebApi.Search;
using CopilotChat.WebApi.Services;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.ApplicationInsights.Extensibility.Implementation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using Serilog;

namespace CopilotChat.WebApi;

public sealed class Program
{
    public static async Task Main(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        IHttpContextAccessor httpContextAccessor = new HttpContextAccessor();

        CopilotApiConfiguration copliotApiConfiguration = ((IConfiguration)builder.Configuration).GetSection(nameof(CopilotApiConfiguration)).Get<CopilotApiConfiguration>() ?? new CopilotApiConfiguration();
        builder.Services.AddSingleton(copliotApiConfiguration);

        AzureSearchConfig azureSearchConfiguration = ((IConfiguration)builder.Configuration).GetSection(nameof(AzureSearchConfig)).Get<AzureSearchConfig>() ?? new AzureSearchConfig();
        builder.Services.AddSingleton(azureSearchConfiguration);

        ChatStoreConfig cosmosConfiguration = ((IConfiguration)builder.Configuration).GetSection("ChatStore").Get<ChatStoreConfig>() ?? new ChatStoreConfig();
        builder.Services.AddSingleton(cosmosConfiguration);

        builder.Host.AddConfiguration();
        builder.WebHost.UseUrls();
        builder.Host.UseSerilog((hostContext, loggerConfig) =>
        {
            loggerConfig
                .ReadFrom.Configuration(hostContext.Configuration)
                .Enrich.WithProperty("ApplicationName", hostContext.HostingEnvironment.ApplicationName);
        }); ;

        builder.Services
            //.AddSingleton<ILogger>(sp => sp.GetRequiredService<ILogger<Program>>())
            .AddOptions(builder.Configuration)
            .AddPersistentChatStore()
            .AddPlugins(builder.Configuration)
            .AddChatCopilotAuthentication(builder.Configuration, httpContextAccessor)
            .AddChatCopilotAuthorization();

        builder
            .AddBotConfig()
            .AddSemanticKernelServices()
            .AddSemanticMemoryServices();

        builder.Services.AddSignalR();
        

        DatabaseConnectionStrings databaseConnectionStrings = ((IConfiguration)builder.Configuration).GetSection("ConnectionStrings").Get<DatabaseConnectionStrings>() ?? new DatabaseConnectionStrings();
        builder.Services.AddDbContext<CopilotDbContext>(delegate (DbContextOptionsBuilder options)
        {
            options.UseSqlServer(databaseConnectionStrings.CurrentSiteConnectionString, delegate (SqlServerDbContextOptionsBuilder sql)
            {
                sql.MigrationsAssembly(typeof(CopilotDbContext).Assembly.FullName);
            });
        });

        //builder.Services.AddTransient<IUserValidator<UserIdentity>, OptionalEmailUserValidator<UserIdentity>>();
        //builder.Services.AddApiAuthentication<CopilotDbContext, UserIdentity, IdentityRole>(builder.Configuration);

        builder.Services
            .AddHttpContextAccessor()
            .AddApplicationInsightsTelemetry(options => { options.ConnectionString = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"]; })
            .AddSingleton<ITelemetryInitializer, AppInsightsUserTelemetryInitializerService>()
            .AddLogging(logBuilder => logBuilder.AddApplicationInsights())
            .AddSingleton<ITelemetryService, AppInsightsTelemetryService>();

        TelemetryDebugWriter.IsTracingDisabled = Debugger.IsAttached;

        builder.Services.AddHttpClient();

        builder.Services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc(copliotApiConfiguration!.ApiVersion, new OpenApiInfo { Title = copliotApiConfiguration.ApiName, Version = copliotApiConfiguration.ApiVersion });

            options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.OAuth2,
                Flows = new OpenApiOAuthFlows
                {
                    AuthorizationCode = new OpenApiOAuthFlow
                    {
                        AuthorizationUrl = new Uri($"{copliotApiConfiguration.IdentityServerBaseUrl}/connect/authorize"),
                        TokenUrl = new Uri($"{copliotApiConfiguration.IdentityServerBaseUrl}/connect/token"),
                        Scopes = new Dictionary<string, string> {
                                { copliotApiConfiguration.OidcApiName, copliotApiConfiguration.ApiName }
                            }
                    }
                }
            });

            options.OperationFilter<AuthorizeCheckOperationFilter>();

        });


        builder.Services.AddScoped<ISearchConnector, SearchConnector>();

        builder.Services
            .AddMaintenanceServices()
            .AddDistributedMemoryCache()
            .AddEndpointsApiExplorer()
            .AddCorsPolicy(builder.Configuration)
            .AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
            });
        builder.Services.AddSession().AddHealthChecks();

        WebApplication app = builder.Build();
        app.AddForwardHeaders();
        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.UseCors();
        app.UseSession();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseMiddleware<MaintenanceMiddleware>();
        app.MapControllers()
            .RequireAuthorization();
        app.MapHealthChecks("/healthz");

        app.MapHub<MessageRelayHub>("/messageRelayHub");

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint($"{copliotApiConfiguration?.ApiBaseUrl}/swagger/v1/swagger.json", copliotApiConfiguration?.ApiName);
                c.OAuthClientId(copliotApiConfiguration?.OidcSwaggerUIClientId);
                c.OAuthAppName(copliotApiConfiguration?.ApiName);
                c.OAuthUsePkce();
            });

            app.MapWhen(
                context => context.Request.Path == "/",
                appBuilder =>
                    appBuilder.Run(
                        async context => await Task.Run(() => context.Response.Redirect("/swagger"))));
        }

        app.Services.DbRegistration();

        Task runTask = app.RunAsync();

        try
        {
            //string? address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.FirstOrDefault();
            //app.Services.GetRequiredService<ILogger>().LogInformation("Health probe: {0}/healthz", address);
        }
        catch (ObjectDisposedException)
        {
        }

        await runTask;
    }

}
