using AspNet.Security.OAuth.Line;
using MongoDB.Bson;
using MongoDB.Driver;
using OIDC_Server.Models.Mongo;
using OIDC_Server.Repositories.Interface;

namespace OIDC_Server.Repositories
{
    public class UserRepository : IUserRepository
    {
        public IMongoCollection<User> UserCollection { get; }

        public UserRepository(IMongoCollection<User> userCollection)
        {
            this.UserCollection = userCollection;
        }

        public async Task<User?> GetUserById(string id)
            => await this.UserCollection.Find(x => x.Id == id).FirstOrDefaultAsync();

        public async Task<User?> GetUserBySubject(string ssoProvider, string subject)
        {
            switch (ssoProvider)
            {
                case LineAuthenticationDefaults.AuthenticationScheme:
                    return await this.UserCollection.Find(x => x.LinkLine.Subject == subject).FirstOrDefaultAsync();
                default:
                    return null;
            }
        }

        public async Task<User?> GetUserByConnectKey(string connectKey)
            => await this.UserCollection.Find(x => x.ConnectKey == connectKey).FirstOrDefaultAsync();

        public async Task Create(User user)
            => await this.UserCollection.InsertOneAsync(user);

        public async Task Update(User user)
            => await this.UserCollection.ReplaceOneAsync(x => x.Id == user.Id, user);

        public async Task Delete(User user)
            => await this.UserCollection.DeleteOneAsync(x => x.Id == user.Id);

    }
}
