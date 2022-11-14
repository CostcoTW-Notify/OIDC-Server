using AspNet.Security.OAuth.Line;
using OIDC_Server.Models.Mongo;
using OIDC_Server.Repositories.Interface;
using OIDC_Server.Services.Interface;
using OpenIddict.Abstractions;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace OIDC_Server.Services
{
    public class UserService : IUserService
    {
        public IUserRepository UserRepo { get; }

        public UserService(IUserRepository userRepo)
        {
            this.UserRepo = userRepo;
        }

        private async Task<User> CreateUser(string name)
        {
            var user = new User
            {
                Name = name,
                CreatedAt = DateTime.Now,
            };

            await this.UserRepo.Create(user);
            return user;
        }

        public async Task<User?> ProcessExternalLogin(ClaimsPrincipal principal)
        {
            switch (principal.Identity!.AuthenticationType)
            {
                case LineAuthenticationDefaults.AuthenticationScheme:
                    {
                        var subject = principal.GetClaim(ClaimTypes.NameIdentifier);
                        var user = await this.UserRepo.GetUserBySubject(LineAuthenticationDefaults.AuthenticationScheme, subject!);
                        if (user is null)
                        {
                            user = await CreateUser(principal.Identity.Name!);
                        }

                        var displayName = principal.GetClaim(ClaimTypes.Name);
                        var picture = principal.GetClaim("urn:line:picture_url");


                        if (user.LinkLine is null)
                        {
                            user.LinkLine = new LineUser
                            {
                                Subject = subject
                            };
                        }

                        user.LinkLine.DisplayName = displayName;
                        user.LinkLine.Picture = picture;

                        if (string.IsNullOrWhiteSpace(user.Name))
                            user.Name = user.LinkLine.DisplayName;
                        if (string.IsNullOrWhiteSpace(user.Picture))
                            user.Picture = user.LinkLine.Picture;

                        user.LastLoginTime = DateTime.Now;
                        await this.UserRepo.Update(user);
                        return user;
                    }
                default:
                    return null;
            }
        }

        public async Task<User?> GetUserById(string id)
            => await this.UserRepo.GetUserById(id);

    }
}
