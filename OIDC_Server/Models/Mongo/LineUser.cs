using MongoDB.Bson.Serialization.Attributes;

namespace OIDC_Server.Models.Mongo
{
    public class LineUser : ExternalUser
    {
        public override string SsoProvider => "Line";

        public string? Picture { get; set; }

        public string? Email { get; set; }

        public DateTime ConnectAt { get; set; }

    }
}
