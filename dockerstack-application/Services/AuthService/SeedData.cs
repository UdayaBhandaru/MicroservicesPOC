// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Linq;
using System.Security.Claims;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Identity.Service.Models;
using Identity.Service.Data;

namespace Identity.Service
{
    public class SeedData
    {
        public static void EnsureSeedData(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
                try
                {
                    var email = (from users in context.Users select users.Email).FirstOrDefault();
                    if (email == null)
                    {
                        context.Database.Migrate();
                    }
                }
                catch (Exception ex)
                {
                    context.Database.Migrate();
                }
            }
        }
    }
}
