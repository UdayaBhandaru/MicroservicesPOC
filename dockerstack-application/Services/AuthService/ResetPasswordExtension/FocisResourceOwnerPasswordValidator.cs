// <copyright file="FocisResourceOwnerPasswordValidator.cs" company="PlaceholderCompany">
// Copyright (c) PlaceholderCompany. All rights reserved.
// </copyright>

namespace Agility.Focis.IdentityServer.ResetPasswordExtension
{
    using System.Threading.Tasks;
    using Agility.Framework.Core.Security.Models;
    using IdentityServer4.AspNetIdentity;
    using IdentityServer4.Events;
    using IdentityServer4.Models;
    using IdentityServer4.Services;
    using IdentityServer4.Validation;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;
    using static IdentityModel.OidcConstants;

    public class FocisResourceOwnerPasswordValidator : ResourceOwnerPasswordValidator<ApplicationUser>
    {
        private readonly SignInManager<ApplicationUser> signInManager;

        private IEventService events;

        public FocisResourceOwnerPasswordValidator(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IEventService events, ILogger<ResourceOwnerPasswordValidator<ApplicationUser>> logger)
            : base(userManager, signInManager, events, logger)
        {
            this.UserManager = userManager;
            this.signInManager = signInManager;
            this.events = events;
        }

        public UserManager<ApplicationUser> UserManager { get; }

        public ILogger<ResourceOwnerPasswordValidator<ApplicationUser>> Logger { get; }

        public override async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            var result = await this.signInManager.PasswordSignInAsync(context.UserName, context.Password, true, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                var sub = await this.UserManager.FindByEmailAsync(context.UserName);

                // this.Logger.LogInformation("Credentials validated for username: {username}", context.UserName);
                await this.events.RaiseAsync(new UserLoginSuccessEvent(context.UserName, sub.Id, context.UserName, interactive: false));

                context.Result = new GrantValidationResult(sub.Id, AuthenticationMethods.Password, null, "local", null);
                return;
            }
            else if (result.IsLockedOut)
            {
                // this.Logger.LogInformation("Authentication failed for username: {username}, reason: locked out", context.UserName);
                await this.events.RaiseAsync(new UserLoginFailureEvent(context.UserName, "locked out", interactive: false));
            }
            else if (result.IsNotAllowed)
            {
                // this.Logger.LogInformation("Authentication failed for username: {username}, reason: not allowed", context.UserName);
                await this.events.RaiseAsync(new UserLoginFailureEvent(context.UserName, "not allowed", interactive: false));
            }
            else
            {
                // this.Logger.LogInformation("Authentication failed for username: {username}, reason: invalid credentials", context.UserName);
                await this.events.RaiseAsync(new UserLoginFailureEvent(context.UserName, "invalid credentials", interactive: false));
            }

            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant);
        }
    }
}