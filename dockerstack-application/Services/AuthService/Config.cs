// <copyright file="Config.cs" company="Agility E Services">
// Copyright (c) Agility E Services. All rights reserved.
// </copyright>

namespace Agility.Framework.IdentityServer
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using IdentityServer4;
    using IdentityServer4.Models;
    using IdentityServer4.Test;

    public static class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile()
            };
        }
    }
}