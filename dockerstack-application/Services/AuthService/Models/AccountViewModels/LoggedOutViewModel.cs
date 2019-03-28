// <copyright file="LoggedOutViewModel.cs" company="Agility E Services">
// Copyright (c) Agility E Services. All rights reserved.
// </copyright>

namespace Agility.Framework.IdentityServer.Models.AccountViewModels
{
    public class LoggedOutViewModel
    {
        public string PostLogoutRedirectUri { get; set; }

        public string ClientName { get; set; }

        public string SignOutIframeUrl { get; set; }

        public bool AutomaticRedirectAfterSignOut { get; set; }

        public string LogoutId { get; set; }

        public bool TriggerExternalSignout => this.ExternalAuthenticationScheme != null;

        public string ExternalAuthenticationScheme { get; set; }
    }
}