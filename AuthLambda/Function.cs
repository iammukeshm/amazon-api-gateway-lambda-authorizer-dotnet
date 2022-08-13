using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DataModel;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace AuthLambda;

public class Function
{


    private const string key = "S0M3RAN0MS3CR3T!1!MAG1C!1!";
    public APIGatewayCustomAuthorizerResponse ValidateTokenAsync(APIGatewayCustomAuthorizerRequest request, ILambdaContext context)
    {
        var authToken = request.Headers["authorization"];
        Console.WriteLine($"token is {authToken}");
        Console.WriteLine($"request is {JsonConvert.SerializeObject(request)}");
        Console.WriteLine($"context is {JsonConvert.SerializeObject(context)}");
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParams = new TokenValidationParameters()
        {
            ValidateLifetime = true,
            ValidateAudience = false,
            ValidateIssuer = false,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
        };
        var claimsPrincipal = tokenHandler.ValidateToken(authToken, validationParams, out SecurityToken securityToken);
        if (claimsPrincipal == null)
        {
            return new APIGatewayCustomAuthorizerResponse()
            {
                PrincipalID = "auth-401",
                PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
                {
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>
                    {
                        new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                        {
                            Effect = "Deny"
                        }
                    }
                }
            };
        }
        else
        {
            return new APIGatewayCustomAuthorizerResponse()
            {
                PrincipalID = claimsPrincipal?.FindFirst(ClaimTypes.Name)?.Value,
                PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
                {
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>
                    {
                        new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                        {
                            Effect = "Allow",
                            Resource = new HashSet<string>{"arn:aws:execute-api:ap-south-1:821175633958:sctmtm1ge8/*/*"},
                            Action = new HashSet<string>{"execute-api:Invoke"}
                        }
                    }
                }
            };
        }
    }

    public async Task<string> GenerateTokenAsync(APIGatewayHttpApiV2ProxyRequest request, ILambdaContext context)
    {
        var tokenRequest = JsonConvert.DeserializeObject<User>(request.Body);
        AmazonDynamoDBClient client = new AmazonDynamoDBClient();
        DynamoDBContext dbContext = new DynamoDBContext(client);

        //check if user exists in ddb
        var user = await dbContext.LoadAsync<User>(tokenRequest?.Email);
        if (user == null) throw new Exception("User Not Found!");
        if (user.Password != tokenRequest.Password) throw new Exception("Invalid Credentials!");

        var token = GenerateJWT(user);
        return token;
    }
    public string GenerateJWT(User user)
    {
        var claims = new List<Claim> { new(ClaimTypes.Email, user.Email), new(ClaimTypes.Name, user.Username) };
        byte[] secret = Encoding.UTF8.GetBytes(key);
        var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(claims: claims, expires: DateTime.UtcNow.AddMinutes(500), signingCredentials: signingCredentials);
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }
}
