// <copyright file="AccountService.cs" company="Agility E Services">
// Copyright (c) Agility E Services. All rights reserved.
// </copyright>

namespace Agility.Framework.IdentityServer
{
    using System.Threading.Tasks;
    using Agility.Framework.IdentityServer.Models.AccountViewModels;
    using IdentityModel;
    using IdentityServer4.Extensions;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;

    public class AccountService
    {
        // private readonly IClientStore clientStore;
        private readonly IIdentityServerInteractionService interaction;
        private readonly IHttpContextAccessor httpContextAccessor;

        // private readonly IAuthenticationSchemeProvider schemeProvider;
        public AccountService(
            IIdentityServerInteractionService interaction,
            IHttpContextAccessor httpContextAccessor,
            IAuthenticationSchemeProvider schemeProvider,
            IClientStore clientStore)
        {
            this.interaction = interaction;
            this.httpContextAccessor = httpContextAccessor;

            // this.schemeProvider = schemeProvider;
            // this.clientStore = clientStore;
        }

        public async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = true };

            var user = this.httpContextAccessor.HttpContext.User;
            if (user?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await this.interaction.GetLogoutContextAsync(logoutId);
            if (context != null && !context.ShowSignoutPrompt)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        public async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await this.interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = true,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = logout?.ClientId,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            var user = this.httpContextAccessor.HttpContext.User;
            if (user?.Identity.IsAuthenticated == true)
            {
                var idp = user.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await this.httpContextAccessor.HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await this.interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}
