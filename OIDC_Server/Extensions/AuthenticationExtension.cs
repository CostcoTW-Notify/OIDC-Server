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
                        var clientId = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.LINE_CLIENT_ID);
                        var secret = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.LINE_CLIENT_SERCET);
                        options.ClientId = clientId!;
                        options.ClientSecret = secret!;

                        options.Events.OnTicketReceived = (context) =>
                        {
                            var rngKey = RandomGenerator.GenerateString(8);
                            var redirectUri = context.ReturnUri?.Substring(0, context.ReturnUri.IndexOf('?') + 1) +
                                              $"sso=line-{rngKey}&" +
                                              context.ReturnUri?.Substring(context.ReturnUri.IndexOf('?') + 1);

                            context.Properties!.SetString("ssoKey", rngKey);
                            context.ReturnUri = redirectUri;
                            return Task.CompletedTask;
                        };
                    })
                    ;

            return services;
        }
    }
}
