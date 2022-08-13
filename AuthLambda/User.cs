using Amazon.DynamoDBv2.DataModel;

namespace AuthLambda
{
    [DynamoDBTable("users")]
    public class User
    {
        [DynamoDBHashKey("email")]
        public string? Email { get; set; }
        [DynamoDBProperty("username")]
        public string? Username { get; set; }
        [DynamoDBProperty("password")]
        public string? Password { get; set; }
    }
}
