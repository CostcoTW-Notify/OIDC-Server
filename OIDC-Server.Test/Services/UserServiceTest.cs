using AspNet.Security.OAuth.Line;
using NSubstitute;
using NSubstitute.ReturnsExtensions;
using OIDC_Server.Models.Mongo;
using OIDC_Server.Repositories.Interface;
using OIDC_Server.Services;
using System.Security.Claims;

namespace OIDC_Server.Test.Services
{
    public class UserServiceTest
    {
        [Fact]
        public async void Test_ProcessExternalLogin_will_return_null_if_ssoProvider_illegal()
        {
            var repo = Substitute.For<IUserRepository>();
            var service = new UserService(repo);
            var principal = new ClaimsPrincipal(new ClaimsIdentity("Google"));

            var user = await service.ProcessExternalLogin(principal);

            Assert.Null(user);
        }


        [Fact]
        public async void Test_ProcessExternalLogin_will_create_new_user_if_user_not_exists()
        {
            var repo = Substitute.For<IUserRepository>();
            var service = new UserService(repo);
            var identity = new ClaimsIdentity(LineAuthenticationDefaults.AuthenticationScheme);

            var userName = "MakotoAtsu";
            var userEmail = "User@gmail.com";
            var pictureUrl = "https://www.google.com";
            var subject = "userSubject";

            identity.AddClaims(new[]
            {
                new Claim(ClaimTypes.NameIdentifier,subject),
                new Claim(ClaimTypes.Name,userName),
                new Claim("urn:line:picture_url",pictureUrl),
                new Claim(ClaimTypes.Email,userEmail),
            });

            repo.GetUserBySubject(String.Empty, String.Empty).ReturnsNull();

            var principal = new ClaimsPrincipal(identity);

            var user = await service.ProcessExternalLogin(principal);

            Assert.NotNull(user);
            await repo.Received(1).Create(Arg.Is<User>(x => x.Name == userName));
            await repo.Received(1).Update(Arg.Is<User>(x => x.Name == userName &&
                                                            x.LinkLine != null &&
                                                            x.LinkLine.Picture == pictureUrl &&
                                                            x.LinkLine.Email == userEmail &&
                                                            x.LinkLine.Subject == subject));
        }
    }
}