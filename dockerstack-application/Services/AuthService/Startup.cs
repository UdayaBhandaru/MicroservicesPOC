// <copyright file="Startup.cs" company="Agility E Services">
// Copyright (c) Agility E Services. All rights reserved.
// </copyright>

namespace Agility.Focis.IdentityServer
{
    using Agility.Focis.IdentityServer.ResetPasswordExtension;
    using Agility.Framework.Core.Common;
    using Agility.Framework.Core.Security.Models;
    using Agility.Framework.IdentityServer.Core;
    using Agility.Framework.IdentityServer.Core.Services;
    using Agility.Framework.Oracle;
    using Agility.Framework.SqlServer;
    using IdentityServer4.AspNetIdentity;
    using IdentityServer4.Services;
    using IdentityServer4.Validation;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;
    using NLog.Web;

    public class Startup : FxIdentityServerStartup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                  .SetBasePath(env.ContentRootPath)
                  .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                  .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                  .AddEnvironmentVariables();
            env.ConfigureNLog("nlog.config");
            this.Startup(env, builder.Build());
        }

        public override void ConfigureServices(IServiceCollection services)
        {
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddTransient<ISmsSender, TwilioSmsSender>();
            services.AddTransient(typeof(IDbStartup), typeof(SqlServerStartup));
            services.AddCors(options => options.AddPolicy("anyOrigin", p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod().AllowCredentials()));
            base.ConfigureServices(services);
            services.AddTransient<IResourceOwnerPasswordValidator, FocisResourceOwnerPasswordValidator>();
            services.AddTransient<AspNetIdentityProfileService, FocisProfileService>();
        }

        public override void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            app.UseCors("anyOrigin");
            base.Configure(app, env, loggerFactory);
        }
    }
}
