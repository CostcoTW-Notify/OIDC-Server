using Microsoft.AspNetCore.DataProtection;
using MongoDB.Driver;
using OIDC_Server.Extensions;
using OIDC_Server.Utility;

EnsureVariableExists();

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDataProtection()
                .PersistKeysToMongoDb(c => c.GetRequiredService<IMongoDatabase>());
builder.Services.SetupOpeniddict();
builder.Services.SetupAuthentication();


builder.Services.AddCors(op =>
{
    op.AddPolicy(
        name: "Allow-GitHub.io-SPA-App",
        policy =>
        {
            policy.WithOrigins(
                "https://costcotw-notify.github.io",
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://192.168.2.6:5173"
                );
            policy.AllowAnyMethod();
            policy.AllowAnyHeader();
        });
});

builder.Host.SetupAutoFac();

var app = builder.Build();


await app.InitOpeniddictDatabase();

// Keep err log  
app.Use(async (context, next) =>
{
    try
    {
        await next.Invoke();
    }
    catch (Exception ex)
    {
        Console.WriteLine("============= Error ============");
        Console.WriteLine("Caught EX: " + ex.Message);
        Console.WriteLine(ex);
        Console.WriteLine("============== End =============");
        throw;
    }

});
// Configure the HTTP request pipeline.
app.UseSwagger();
app.UseSwaggerUI();

app.UseCors("Allow-GitHub.io-SPA-App");

app.UseAuthentication();
app.UseAuthorization();
app.UseOpeniddictRoute();
app.MapControllers();

app.Run();


static void EnsureVariableExists()
{
    var mongo_conn_str = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.MONGO_CONN_STR);
    var client_id = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.LINE_CLIENT_ID);
    var client_sercet = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.LINE_CLIENT_SERCET);

    if (string.IsNullOrWhiteSpace(mongo_conn_str))
        throw new ArgumentException($"env: {EnvironmentVariableKeys.MONGO_CONN_STR} not setup...");

    if (string.IsNullOrWhiteSpace(client_id))
        throw new ArgumentException($"env: {EnvironmentVariableKeys.LINE_CLIENT_ID} not setup...");

    if (string.IsNullOrWhiteSpace(client_sercet))
        throw new ArgumentException($"env: {EnvironmentVariableKeys.LINE_CLIENT_SERCET} not setup...");
}