using Autofac;
using Autofac.Extensions.DependencyInjection;
using MongoDB.Driver;
using OIDC_Server.Utility;

namespace OIDC_Server.Extensions
{
    public static class AutoFacExtension
    {

        public static IHostBuilder SetupAutoFac(this IHostBuilder host)
        => host.UseServiceProviderFactory(new AutofacServiceProviderFactory())
               .ConfigureContainer<ContainerBuilder>(builder =>
               {
                   var connStr = Environment.GetEnvironmentVariable(EnvironmentVariableKeys.MONGO_CONN_STR);

                   builder.Register(c =>
                   {
                       var mongoUrl = new MongoUrl(connStr);
                       var db = new MongoClient(mongoUrl).GetDatabase(mongoUrl.DatabaseName);
                       return db;
                   }).AsImplementedInterfaces().SingleInstance();


               });
    }
}
