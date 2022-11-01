using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Options;
using OIDC_Server.Services.Interface;
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
            ISystemClock clock,
            IUserService service)
            : base(options, logger, encoder, clock)
        {
            this.UserService = service;
        }

        public IUserService UserService { get; }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            Console.WriteLine($"Timeout is {Options.SSOLoginTimeout}");

            var ssoData = Request.Query["sso"].ToString();

            if (string.IsNullOrWhiteSpace(ssoData))
                return AuthenticateResult.NoResult();


            var ssoInfo = ssoData.Split('-');
            if (ssoInfo.Length != 2)
                return AuthenticateResult.Fail("Bad Request..");
            var ssoProvider = ssoInfo.First();
            var connectKey = ssoInfo.Last();

            //connectKey = connectKey.ToLower();
            var user = await this.UserService.GetUserByConnectKey(connectKey);

            if (user is null)
                return AuthenticateResult.Fail("ConnectKey invalid");
           
            if ((DateTimeOffset.Now - user.LastLoginTime) > Options.SSOLoginTimeout)
                return AuthenticateResult.Fail("Login timeout");


            var identity = new ClaimsIdentity(
                authenticationType: ssoProvider,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.AddClaim(new Claim(Claims.AuthenticationMethodReference, ssoProvider));
            identity.AddClaim(new Claim(Claims.Subject, user.Id!));
            identity.AddClaim(new Claim(Claims.Name, user.Name!));
            if (!string.IsNullOrWhiteSpace(user.Email))
                identity.AddClaim(new Claim(Claims.Email, user.Email));
            if (!string.IsNullOrWhiteSpace(user.Picture))
                identity.AddClaim(new Claim(Claims.Picture, user.Picture.ToString()));

            var claimsPrincipal = new ClaimsPrincipal(identity);

            var authenticationTicket = new AuthenticationTicket(claimsPrincipal, SSOLoginAuthenticationDefaults.AuthenticationScheme);

            return AuthenticateResult.Success(authenticationTicket);
        }

        protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
        {
            // Connect login key to user
            await this.UserService.ProcessExternalLogin(user, properties!.GetString("ssoKey")!);
        }

        protected override Task HandleSignOutAsync(AuthenticationProperties? properties)
        {
            return Task.CompletedTask;
        }
    }
}
