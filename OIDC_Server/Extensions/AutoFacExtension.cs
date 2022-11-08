using Autofac;
using Autofac.Extensions.DependencyInjection;
using MongoDB.Driver;
using OIDC_Server.Models.Mongo;
using OIDC_Server.Repositories;
using OIDC_Server.Services;
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
                       var db = new MongoClient(mongoUrl).GetDatabase("OIDC-Server");
                       return db;
                   }).AsImplementedInterfaces().SingleInstance();

                   builder.Register(c => c.Resolve<IMongoDatabase>()
                                          .GetCollection<User>(MongoCollectionName.Users))
                          .AsImplementedInterfaces().SingleInstance();

                   builder.RegisterType<UserRepository>().AsImplementedInterfaces().InstancePerLifetimeScope();
                   builder.RegisterType<UserService>().AsImplementedInterfaces().InstancePerLifetimeScope();
               });
    }
}
