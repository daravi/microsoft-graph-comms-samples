// <copyright file="MsalTokenProvider.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
// </copyright>

namespace Sample.Common.Authentication
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;

    /// <summary>
    /// Token provider that wraps a pre-built <see cref="IConfidentialClientApplication"/>
    /// for acquiring OAuth 2.0 client-credential tokens via MSAL.
    /// </summary>
    public class MsalTokenProvider
    {
        /// <summary>
        /// The MSAL confidential client application.
        /// </summary>
        private readonly IConfidentialClientApplication msalApp;

        /// <summary>
        /// Initializes a new instance of the <see cref="MsalTokenProvider"/> class.
        /// </summary>
        /// <param name="msalApp">The MSAL confidential client application.</param>
        public MsalTokenProvider(IConfidentialClientApplication msalApp)
        {
            this.msalApp = msalApp ?? throw new ArgumentNullException(nameof(msalApp));
        }

        /// <summary>
        /// Acquires a token for the specified scopes and tenant.
        /// </summary>
        /// <param name="tenant">The tenant identifier (or "common").</param>
        /// <param name="scopes">The scopes to request.</param>
        /// <returns>The <see cref="AuthenticationResult"/>.</returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string tenant, string[] scopes)
        {
            const string replaceString = "{tenant}";
            const string oauthV2TokenLink = "https://login.microsoftonline.com/{tenant}";

            tenant = string.IsNullOrWhiteSpace(tenant) ? "common" : tenant;
            var tokenLink = oauthV2TokenLink.Replace(replaceString, tenant);

            return await this.msalApp.AcquireTokenForClient(scopes)
                .WithAuthority(tokenLink)
                .ExecuteAsync()
                .ConfigureAwait(false);
        }
    }
}
