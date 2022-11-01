using OIDC_Server.Models.Mongo;

namespace OIDC_Server.Repositories.Interface
{
    public interface IUserRepository
    {

        public Task<User?> GetUserById(string id);

        public Task<User?> GetUserBySubject(string ssoProvider, string subject);

        public Task<User?> GetUserByConnectKey(string connectKey);

        public Task Create(User user);

        public Task Update(User user);

        public Task Delete(User user);


    }
}
