using OIDC_Server.Models.Mongo;
using System.Diagnostics.CodeAnalysis;

namespace OIDC_Server.Repositories.Interface
{
    public interface IUserRepository
    {

        public Task<User?> GetUserById([DisallowNull] string id);

        public Task<User?> GetUserBySubject([DisallowNull] string ssoProvider, [DisallowNull] string subject);

        public Task Create(User user);

        public Task Update(User user);

        public Task Delete(User user);


    }
}
