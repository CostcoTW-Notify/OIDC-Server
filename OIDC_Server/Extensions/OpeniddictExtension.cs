using Microsoft.Extensions.Options;
using MongoDB.Driver;
using OpenIddict.Abstractions;
using OpenIddict.MongoDb.Models;
using OpenIddict.MongoDb;
using static OpenIddict.Abstractions.OpenIddictConstants;
using AspNet.Security.OAuth.Line;
using Microsoft.AspNetCore.Authentication;
using OIDC_Server.Utility.SSOLoginAuthentication;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using OpenIddict.Validation.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using OIDC_Server.Services.Interface;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace OIDC_Server.Extensions
{
    public static class OpeniddictExtension
    {

        public static IServiceCollection SetupOpeniddict(this IServiceCollection services)
        {
            services.AddOpenIddict()
                    .AddCore(options =>
                    {
                        options.UseMongoDb();
                    })
                    .AddServer(options =>
                    {
                        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == Environments.Development)
                        {
                            // For develop
                            options.AddDevelopmentEncryptionCertificate()
                                   .AddDevelopmentSigningCertificate();
                        }
                        else
                        {
                            var rsaKey = RSA.Create();
                            rsaKey.ImportFromPem(File.ReadAllText("RSA.pem").ToCharArray());
                            options.AddSigningKey(new RsaSecurityKey(rsaKey));
                            options.AddEncryptionKey(new RsaSecurityKey(rsaKey));
                        }

                        //var hs256Key = File.ReadAllText("HS256.key");
                        options.AddSigningKey(new SymmetricSecurityKey(File.ReadAllBytes("HS256.key")));

                        // Support OIDC Flow
                        options.AllowAuthorizationCodeFlow()
                               .AllowClientCredentialsFlow()
                               .AllowRefreshTokenFlow();

                        // Url setting
                        options.SetTokenEndpointUris("/oidc/token")
                               .SetAuthorizationEndpointUris(new[] { "/oidc/authorize/line" })
                               .SetUserinfoEndpointUris("/oidc/userinfo")
                               .SetLogoutEndpointUris("/oidc/sign-out")
                               ;


                        options.UseAspNetCore()
                               .DisableTransportSecurityRequirement()
                               .EnableAuthorizationEndpointPassthrough()
                               .EnableUserinfoEndpointPassthrough()
                               //.EnableLogoutEndpointPassthrough()
                               ;

                        // Token expire setting
                        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(30))
                               .SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(10))
                               .SetRefreshTokenLifetime(TimeSpan.FromDays(1))
                               .DisableAccessTokenEncryption()
                               ;

                        // Database setting
                        options.DisableAuthorizationStorage();

                    })
                    .AddValidation(options =>
                    {
                        options.UseLocalServer();
                        options.UseAspNetCore();
                    });

            return services;
        }

        public static WebApplication UseOpeniddictRoute(this WebApplication app)
        {
            app.MapGet("/oidc/authorize/{ssoProvider}", async (HttpContext context, string ssoProvider) =>
            {

                var principal = (await context.AuthenticateAsync(SSOLoginAuthenticationDefaults.AuthenticationScheme))?.Principal;
                if (principal is null)
                    switch (ssoProvider.ToLower())
                    {
                        case "line":
                            return Results.Challenge(properties: null, new[] { LineAuthenticationDefaults.AuthenticationScheme });
                        default:
                            return Results.BadRequest("SSO Provider is invalid..");
                    }

                var tokenPrincipal = new ClaimsPrincipal(principal);

                foreach (var claim in tokenPrincipal.Claims)
                {
                    if (claim.Type == Claims.Subject || claim.Type == Claims.Name)
                        claim.SetDestinations(Destinations.AccessToken);
                    claim.SetDestinations(Destinations.IdentityToken);
                }


                return Results.SignIn(tokenPrincipal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            });


            app.MapGet("/oidc/userinfo", [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
            async (HttpContext context, ClaimsPrincipal principal, IUserService service) =>
            {
                var userId = principal.GetClaim(Claims.Subject)!;
                var user = await service.GetUserById(userId);
                return new
                {
                    sub = userId,
                    name = user?.Name,
                    picture = user?.Picture
                };
            });

            return app;
        }

        public async static Task<WebApplication> InitOpeniddictDatabase(this WebApplication app)
        {

            await app.Services.InitDBSchema();

            await app.Services.CreateDefaultClient();

            return app;
        }

        private async static Task<IServiceProvider> InitDBSchema(this IServiceProvider provider)
        {
            var context = provider.GetRequiredService<IOpenIddictMongoDbContext>();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictMongoDbOptions>>().CurrentValue;
            var database = await context.GetDatabaseAsync(CancellationToken.None);

            var collections = database.ListCollectionNames().ToList();

            if (!collections.Contains(options.ApplicationsCollectionName))
            {
                var applications = database.GetCollection<OpenIddictMongoDbApplication>(options.ApplicationsCollectionName);
                await applications.Indexes.CreateManyAsync(new[]
                {
                    new CreateIndexModel<OpenIddictMongoDbApplication>(
                        Builders<OpenIddictMongoDbApplication>.IndexKeys.Ascending(application => application.ClientId),
                        new CreateIndexOptions
                        {
                            Unique = true
                        }),

                    new CreateIndexModel<OpenIddictMongoDbApplication>(
                        Builders<OpenIddictMongoDbApplication>.IndexKeys.Ascending(application => application.PostLogoutRedirectUris),
                        new CreateIndexOptions
                        {
                            Background = true
                        }),

                    new CreateIndexModel<OpenIddictMongoDbApplication>(
                        Builders<OpenIddictMongoDbApplication>.IndexKeys.Ascending(application => application.RedirectUris),
                        new CreateIndexOptions
                        {
                            Background = true
                        })
                });
            }

            if (!collections.Contains(options.AuthorizationsCollectionName))
            {
                var authorizations = database.GetCollection<OpenIddictMongoDbAuthorization>(options.AuthorizationsCollectionName);
                await authorizations.Indexes.CreateOneAsync(
                    new CreateIndexModel<OpenIddictMongoDbAuthorization>(
                        Builders<OpenIddictMongoDbAuthorization>.IndexKeys
                            .Ascending(authorization => authorization.ApplicationId)
                            .Ascending(authorization => authorization.Scopes)
                            .Ascending(authorization => authorization.Status)
                            .Ascending(authorization => authorization.Subject)
                            .Ascending(authorization => authorization.Type),
                        new CreateIndexOptions
                        {
                            Background = true
                        }));
            }

            if (!collections.Contains(options.ScopesCollectionName))
            {
                var scopes = database.GetCollection<OpenIddictMongoDbScope>(options.ScopesCollectionName);

                await scopes.Indexes.CreateOneAsync(new CreateIndexModel<OpenIddictMongoDbScope>(
                    Builders<OpenIddictMongoDbScope>.IndexKeys.Ascending(scope => scope.Name),
                    new CreateIndexOptions
                    {
                        Unique = true
                    }));
            }

            if (!collections.Contains(options.TokensCollectionName))
            {
                var tokens = database.GetCollection<OpenIddictMongoDbToken>(options.TokensCollectionName);

                await tokens.Indexes.CreateManyAsync(new[]
                {
                    new CreateIndexModel<OpenIddictMongoDbToken>(
                        Builders<OpenIddictMongoDbToken>.IndexKeys.Ascending(token => token.ReferenceId),
                        new CreateIndexOptions<OpenIddictMongoDbToken>
                        {
                            // Note: partial filter expressions are not supported on Azure Cosmos DB.
                            // As a workaround, the expression and the unique constraint can be removed.
                            PartialFilterExpression = Builders<OpenIddictMongoDbToken>.Filter.Exists(token => token.ReferenceId),
                            Unique = true
                        }),

                    new CreateIndexModel<OpenIddictMongoDbToken>(
                        Builders<OpenIddictMongoDbToken>.IndexKeys
                            .Ascending(token => token.ApplicationId)
                            .Ascending(token => token.Status)
                            .Ascending(token => token.Subject)
                            .Ascending(token => token.Type),
                        new CreateIndexOptions
                        {
                            Background = true
                        })
                });
            }

            return provider;
        }

        private async static Task<IServiceProvider> CreateDefaultClient(this IServiceProvider provider)
        {
            const string default_client = "github-io-client";

            await using (var scope = provider.CreateAsyncScope())
            {
                var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

                if ((await manager.FindByClientIdAsync(default_client)) is null)
                    await manager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        DisplayName = "Github IO front-end app",
                        ClientId = default_client,
                        RedirectUris = { new Uri("http://localhost:8914/"), new Uri("https://oauth.pstmn.io/v1/callback") },
                        Permissions =
                        {
                            Permissions.Endpoints.Authorization,
                            Permissions.Endpoints.Token,
                            Permissions.Endpoints.Logout,

                            Permissions.GrantTypes.AuthorizationCode,
                            Permissions.GrantTypes.RefreshToken,

                            Permissions.ResponseTypes.Code,
                            Permissions.Prefixes.Scope + "line_notify"
                        }
                    });
            }
            return provider;
        }
    }
}
