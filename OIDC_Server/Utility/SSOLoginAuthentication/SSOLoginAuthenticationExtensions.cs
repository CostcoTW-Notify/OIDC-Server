using Microsoft.AspNetCore.Authentication;

namespace OIDC_Server.Utility.SSOLoginAuthentication
{
    public static class SSOLoginAuthenticationExtensions
    {
        public static AuthenticationBuilder AddSSOLogin(this AuthenticationBuilder builder,
                        Action<SSOLoginAuthenticationSchemeOptions> configureOptions)
        {
            return builder.AddScheme<SSOLoginAuthenticationSchemeOptions, SSOLoginAuthenticationHandler>
                (SSOLoginAuthenticationDefaults.AuthenticationScheme, SSOLoginAuthenticationDefaults.DisplayName, configureOptions);
        }

        public static AuthenticationBuilder AddSSOLogin(this AuthenticationBuilder builder)
            => builder.AddSSOLogin(option => { });
    }
}
