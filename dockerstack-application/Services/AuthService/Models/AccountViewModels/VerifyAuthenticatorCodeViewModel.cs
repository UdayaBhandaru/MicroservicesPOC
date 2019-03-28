// <copyright file="VerifyAuthenticatorCodeViewModel.cs" company="Agility E Services">
// Copyright (c) Agility E Services. All rights reserved.
// </copyright>

namespace Agility.Framework.IdentityServer.Models.AccountViewModels
{
    using System.ComponentModel.DataAnnotations;

    public class VerifyAuthenticatorCodeViewModel
    {
        [Required]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }

        [Display(Name = "Remember this browser?")]
        public bool RememberBrowser { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
