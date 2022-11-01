using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OIDC_Server.Utility.SSOLoginAuthentication
{
    public class SSOLoginAuthenticationHandler : SignInAuthenticationHandler<SSOLoginAuthenticationSchemeOptions>
    {
        public SSOLoginAuthenticationHandler(
            IOptionsMonitor<SSOLoginAuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            Console.WriteLine($"Timeout is {Options.SSOLoginTimeout}");
            var timeout = false;

            var ssoData = Request.Query["sso"].ToString();

            if (timeout)
                return AuthenticateResult.Fail("Login timeout");


            if (string.IsNullOrWhiteSpace(ssoData))
                return AuthenticateResult.NoResult();

            var ssoInfo = ssoData.Split('-');
            if (ssoInfo.Length != 2)
                return AuthenticateResult.Fail("Bad Request..");
            var ssoProvider = ssoInfo.First();
            var userId = ssoInfo.Last();

            var identity = new ClaimsIdentity(
                authenticationType: ssoProvider,
                nameType: Claims.Name,
                roleType: Claims.Role);


            var claims = new List<Claim>
            {
                new Claim(Claims.Subject,userId),
                new Claim(Claims.Name, "SSO-User Name"),
                new Claim(Claims.Email,"SSO@gmail.com"),
                new Claim(Claims.Picture,"http://picture.com"),
                new Claim(Claims.AuthenticationMethodReference,identity.AuthenticationType!)
            };

            identity.AddClaims(claims);

            var claimsPrincipal = new ClaimsPrincipal(identity);

            var authenticationTicket = new AuthenticationTicket(claimsPrincipal, SSOLoginAuthenticationDefaults.AuthenticationScheme);

            return AuthenticateResult.Success(authenticationTicket);
        }

        protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
        {
            // Store User


            //this.Response


            //throw new NotImplementedException();
        }

        protected override async Task HandleSignOutAsync(AuthenticationProperties? properties)
        {
            Console.WriteLine("SignOut!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            //throw new NotImplementedException();
        }
    }
}
