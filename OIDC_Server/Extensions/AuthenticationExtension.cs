using Microsoft.AspNetCore.Authentication.Cookies;
using OIDC_Server.Utility;

namespace OIDC_Server.Extensions
{
    public static class AuthenticationExtension
    {
        public static IServiceCollection SetupAuthentication(this IServiceCollection services)
        {
            services.AddAuthorization()
                    .AddAuthentication()
                    .AddCookie()
                    .AddLine(options =>
                    {
                        // Because we are run HTTP in docker and Hosting on GCP Cloud Run with HTTPS 
                        options.CorrelationCookie.SameSite = SameSiteMode.Unspecified;
                        var clientId = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.LINE_CLIENT_ID);
                        var secret = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.LINE_CLIENT_SERCET);
                        options.ClientId = clientId!;
                        options.ClientSecret = secret!;
                        options.Scope.Add("email");
                        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                    })
                    ;

            return services;
        }
    }
}
