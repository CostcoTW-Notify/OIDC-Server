using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace OIDC_Server.Models.Mongo
{
    [BsonIgnoreExtraElements]
    public class User
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; }

        public string? Name { get; set; }

        public string? Email { get; set; }

        public string? Picture { get; set; }

        public DateTime? CreatedAt { get; set; }

        public string? ConnectKey { get; set; }

        public DateTime? LastLoginTime { get; set; }

        public LineUser? LinkLine { get; set; }
    }
}
