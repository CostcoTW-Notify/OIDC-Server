using Microsoft.AspNetCore.Authentication;

namespace OIDC_Server.Utility.SSOLoginAuthentication
{
    public class SSOLoginAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {

        /// <summary>
        /// SSO Login expire time
        /// </summary>
        public TimeSpan SSOLoginTimeout { get; set; } = TimeSpan.FromMinutes(10);
    }
}
