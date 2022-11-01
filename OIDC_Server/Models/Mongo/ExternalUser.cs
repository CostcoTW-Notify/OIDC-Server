using MongoDB.Bson.Serialization.Attributes;

namespace OIDC_Server.Models.Mongo
{
    [BsonDiscriminator(Required = true)]
    [BsonKnownTypes(typeof(LineUser))]
    public abstract class ExternalUser
    {
        public abstract string SsoProvider { get; }

        public string? Subject { get; set; }

        public string? DisplayName { get; set; }

        public DateTime CreateAt { get; set; }
    }
}
