using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Orders.Application.Commands;
using Orders.Application.Filters;
using Orders.Application.Services;
using Orders.Application.Validation;
using Orders.Domain.AggregatesModel.BuyerAggregate;
using Orders.Domain.AggregatesModel.OrderAggregate;
using Orders.Infrastructure;
using Orders.Infrastructure.Repositories;
using StackExchange.Redis;

namespace Orders.Application
{
    public partial class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }
        
        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Take connection string from environment varible by default
            var connectionString = Environment.GetEnvironmentVariable("CONNECTION_STRING");

            // Otherwise take from the local configuration (service testing)
            if (string.IsNullOrEmpty(connectionString))
                connectionString = Configuration.GetConnectionString("DefaultConnection");
            
            services.AddEntityFrameworkSqlServer().AddDbContext<OrdersContext>(options =>
            {
                options.UseSqlServer(
                    connectionString,
                    opts =>
                    {
                        opts.MigrationsAssembly(typeof(Startup).GetTypeInfo().Assembly.GetName().Name);
                        opts.EnableRetryOnFailure(maxRetryCount: 10, maxRetryDelay: TimeSpan.FromSeconds(30), errorNumbersToAdd: null);                        
                    });
            });

            // Setup Token validation
            
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        // Add the access_token as a claim, as we may actually need it
                        var accessToken = context.SecurityToken as JwtSecurityToken;
                        if (accessToken != null)
                        {
                            ClaimsIdentity identity = context.Principal.Identity as ClaimsIdentity;
                            if (identity != null)
                            {
                                identity.AddClaim(new Claim("access_token", accessToken.RawData));
                            }
                        }

                        return Task.CompletedTask;
                    }
                };
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidIssuer = Configuration.GetSection("TokenAuthentication:Issuer").Value,
                    ValidateAudience = true,
                    ValidAudience = "api",
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
            });

            // Setup MVC 
            services.AddMvc(options =>
           {
               options.Filters.Add(typeof(HttpGlobalExceptionHandlingFilter));
           });
                

            // Add cors and create Policy with options
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials() );
            });

            // Take Redis connection string from environment varible by default
            var redisConnectionString = Environment.GetEnvironmentVariable("REDIS_CONNECTION");
            // Otherwise take from the local configuration
            if (string.IsNullOrEmpty(redisConnectionString))
                redisConnectionString = Configuration.GetConnectionString("Redis");
            
            services.AddSingleton(sp =>
            {
                return ConnectionMultiplexer.Connect(redisConnectionString);
            });

            // Adding services to DI container
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddTransient<IOrderingIntegrationEventService, OrderingIntegrationService>();
            services.AddTransient<IIdentityService, IdentityService>();
            services.AddScoped<IBuyerRepository, BuyerRepository>();
            services.AddScoped<IOrderRepository, OrderRepository>();    /* Orders respository */
            services.AddSingleton<IConfiguration>(Configuration); /* Make project configuration available */
            
            // Register all integration event handlers for this microservice
            RegisterIntegrationEventHandlers(services);
            
            services.AddOptions();

            // MediatR config
            
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug(LogLevel.Trace);
            
            app.UseCors("CorsPolicy");

            app.UseAuthentication();
            // Log actions
            app.UseMiddleware<RequestLoggingMiddleware>();
            app.UseMiddleware<ResponseLoggingMiddleware>();

            app.UseMvc();
        }

        private void RegisterIntegrationEventHandlers(IServiceCollection services)
        {
            
        }
    }
}