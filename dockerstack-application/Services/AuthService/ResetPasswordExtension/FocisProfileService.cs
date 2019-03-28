// <copyright file="FocisProfileService.cs" company="PlaceholderCompany">
// Copyright (c) PlaceholderCompany. All rights reserved.
// </copyright>

namespace Agility.Focis.IdentityServer.ResetPasswordExtension
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Agility.Framework.Core.Security.Models;
    using Agility.Framework.IdentityServer.Core.Services;
    using Agility.Framework.Web.Security.Identity;
    using Agility.Framework.Web.Security.Repositories;
    using IdentityModel;
    using IdentityServer4.Extensions;
    using IdentityServer4.Models;
    using IdentityServer4.Services;
    using Microsoft.AspNetCore.Identity;

    public class FocisProfileService : AspNetIdentityProfileService

    {
        private readonly UserManager<ApplicationUser> userManager;

        // private SecurityRepository securityRepository;
        private string sessionId;

        public FocisProfileService(UserManager<ApplicationUser> userManager, SecurityRepository securityRepository)
            : base(userManager, securityRepository)
        {
            this.userManager = userManager;

            // this.securityRepository = securityRepository;
        }

        public async new Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            ClaimsPrincipal subject = context.Subject;
            if (subject == null)
            {
                string subjectName = nameof(context.Subject);
                throw new ArgumentNullException(subjectName);
            }

            var subjectId = subject.GetSubjectId();

            var user = await this.userManager.FindByIdAsync(subjectId);
            if (user == null)
            {
                throw new ArgumentException("Invalid subject identifier");
            }

            this.sessionId = subject.Claims.Where(c => c.Type == FxClaimTypes.UserSessionIdentifier).Select(c => c.Value).SingleOrDefault();

            var claims = await this.GetClaimsFromUser(user);

            context.IssuedClaims = claims.ToList();
        }

        public async new Task IsActiveAsync(IsActiveContext context)
        {
            var subject = context.Subject;
            if (subject == null)
            {
                string subjectName = nameof(context.Subject);
                throw new ArgumentNullException(subjectName);
            }

            var subjectId = subject.GetSubjectId();
            var user = await this.userManager.FindByIdAsync(subjectId);

            context.IsActive = false;

            if (user != null)
            {
                if (this.userManager.SupportsUserSecurityStamp)
                {
                    var security_stamp = subject.Claims.Where(c => c.Type == "security_stamp").Select(c => c.Value).SingleOrDefault();
                    if (security_stamp != null)
                    {
                        var db_security_stamp = await this.userManager.GetSecurityStampAsync(user);
                        if (db_security_stamp != security_stamp)
                        {
                            return;
                        }
                    }
                }

                context.IsActive =
                    !user.LockoutEnabled ||
                    !user.LockoutEnd.HasValue ||
                    user.LockoutEnd <= DateTime.Now;
            }
        }

        private async Task<IEnumerable<Claim>> GetClaimsFromUser(ApplicationUser user)
        {
            if (this.sessionId == null)
            {
                this.sessionId = Guid.NewGuid().ToString();
            }

            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, user.Id),
                new Claim(JwtClaimTypes.PreferredUserName, user.UserName),
                new Claim(FxClaimTypes.UserSessionIdentifier, this.sessionId)
            };

            if (this.userManager.SupportsUserEmail)
            {
                claims.AddRange(new[]
                {
                    new Claim(JwtClaimTypes.Email, user.Email)
                });
            }

            if (this.userManager.SupportsUserPhoneNumber && !string.IsNullOrWhiteSpace(user.PhoneNumber))
            {
                claims.AddRange(new[]
                {
                    new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber),
                    new Claim(JwtClaimTypes.PhoneNumberVerified, user.PhoneNumberConfirmed ? "true" : "false", ClaimValueTypes.Boolean)
                });
            }

            if (this.userManager.SupportsUserClaim)
            {
                claims.AddRange(await this.userManager.GetClaimsAsync(user));
            }

            return claims;
        }
    }
}
