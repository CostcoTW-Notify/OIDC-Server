using OIDC_Server.Models.Mongo;
using System.Security.Claims;

namespace OIDC_Server.Services.Interface
{
    public interface IUserService
    {

        public Task ProcessExternalLogin(ClaimsPrincipal user, string connectKey);

        public Task<User?> GetUserByConnectKey(string connectKey);

        public Task<User?> GetUserById(string id);
    }
}
