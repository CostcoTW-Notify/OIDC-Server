using OIDC_Server.Models.Mongo;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace OIDC_Server.Services.Interface
{
    public interface IUserService
    {

        public Task<User> ProcessExternalLogin(ClaimsPrincipal principal);

        public Task<User?> GetUserById([DisallowNull] string id);
    }
}
