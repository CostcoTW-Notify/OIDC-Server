using AspNet.Security.OAuth.Line;
using OIDC_Server.Utility;
using OIDC_Server.Utility.SSOLoginAuthentication;

namespace OIDC_Server.Extensions
{
    public static class AuthenticationExtension
    {
        public static IServiceCollection SetupAuthentication(this IServiceCollection services)
        {
            services.AddAuthorization()
                    .AddAuthentication(SSOLoginAuthenticationDefaults.AuthenticationScheme)
                    .AddSSOLogin(options =>
                    {
                        options.SSOLoginTimeout = TimeSpan.FromMinutes(1);
                    })
                    .AddLine(options =>
                    {
                        // Because we are run HTTP in docker and Hosting on GCP Cloud Run with HTTPS 
                        options.CorrelationCookie.SameSite = SameSiteMode.Unspecified;
                        var clientId = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.LINE_CLIENT_ID);
                        var secret = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.LINE_CLIENT_SERCET);
                        options.ClientId = clientId!;
                        options.ClientSecret = secret!;
                        options.Scope.Add("email");

                        options.Events.OnTicketReceived = (context) =>
                        {
                            var rngKey = RandomGenerator.GenerateString(8);
                            var redirectUri = context.ReturnUri?.Substring(0, context.ReturnUri.IndexOf('?') + 1) +
                                              $"sso={LineAuthenticationDefaults.AuthenticationScheme}-{rngKey}&" +
                                              context.ReturnUri?.Substring(context.ReturnUri.IndexOf('?') + 1);

                            var query = context.ReturnUri!.Split('?').Last()
                                                         .Split('&')
                                                         .Where(x => !x.StartsWith("sso="))
                                                         .ToList();

                            query.Insert(0, $"sso={LineAuthenticationDefaults.AuthenticationScheme}-{rngKey}");

                            context.Properties!.SetString("ssoKey", rngKey);
                            context.ReturnUri = redirectUri!.Split('?').First() + "?" + string.Join("&", query);
                            return Task.CompletedTask;
                        };
                    })
                    ;

            return services;
        }
    }
}
