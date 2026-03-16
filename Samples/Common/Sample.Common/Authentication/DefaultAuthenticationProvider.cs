// <copyright file="DefaultAuthenticationProvider.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
// </copyright>

namespace Sample.Common.Authentication
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Graph.Communications.Client.Authentication;
    using Microsoft.Graph.Communications.Common;
    using Microsoft.Graph.Communications.Common.Telemetry;
    using Microsoft.IdentityModel.Protocols;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// Default authentication provider that uses <see cref="MsalTokenProvider"/>
    /// for outbound token acquisition and validates inbound requests via
    /// Skype/Graph OpenID Connect configuration.
    /// </summary>
    /// <remarks>
    /// This replaces the obsolete <see cref="AuthenticationProvider"/> by accepting
    /// a pre-built <see cref="MsalTokenProvider"/> instead of raw app credentials.
    /// The MSAL app is constructed once and reused, which allows MSAL to cache tokens
    /// internally rather than building a new confidential client on every request.
    /// </remarks>
    /// <seealso cref="IRequestAuthenticationProvider" />
    public class DefaultAuthenticationProvider : ObjectRoot, IRequestAuthenticationProvider
    {
        /// <summary>
        /// The application identifier.
        /// </summary>
        private readonly string appId;

        /// <summary>
        /// The token provider.
        /// </summary>
        private readonly MsalTokenProvider tokenProvider;

        /// <summary>
        /// The open ID configuration refresh interval.
        /// </summary>
        private readonly TimeSpan openIdConfigRefreshInterval = TimeSpan.FromHours(2);

        /// <summary>
        /// The previous update timestamp for OpenIdConfig.
        /// </summary>
        private DateTime prevOpenIdConfigUpdateTimestamp = DateTime.MinValue;

        /// <summary>
        /// The open identifier configuration.
        /// </summary>
        private OpenIdConnectConfiguration openIdConfiguration;

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultAuthenticationProvider"/> class.
        /// </summary>
        /// <param name="appId">The application identifier.</param>
        /// <param name="tokenProvider">The MSAL token provider.</param>
        /// <param name="logger">The graph logger.</param>
        public DefaultAuthenticationProvider(string appId, MsalTokenProvider tokenProvider, IGraphLogger logger)
            : base(logger.NotNull(nameof(logger)).CreateShim(nameof(DefaultAuthenticationProvider)))
        {
            this.appId = appId.NotNullOrWhitespace(nameof(appId));
            this.tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        }

        /// <summary>
        /// Authenticates the specified outbound request message by acquiring
        /// an OAuth 2.0 bearer token via the <see cref="MsalTokenProvider"/>.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="tenant">The tenant.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        public async Task AuthenticateOutboundRequestAsync(HttpRequestMessage request, string tenant)
        {
            const string schema = "Bearer";
            const string resource = "https://graph.microsoft.com";
            var scopes = new string[] { $"{resource}/.default" };

            this.GraphLogger.Info("DefaultAuthenticationProvider: Generating OAuth token.");

            try
            {
                var result = await this.tokenProvider.AcquireTokenAsync(tenant, scopes).ConfigureAwait(false);
                this.GraphLogger.Info($"DefaultAuthenticationProvider: Generated OAuth token. Expires in {result.ExpiresOn.Subtract(DateTimeOffset.UtcNow).TotalMinutes} minutes.");
                request.Headers.Authorization = new AuthenticationHeaderValue(schema, result.AccessToken);
            }
            catch (Exception ex)
            {
                this.GraphLogger.Error(ex, $"Failed to generate token for client: {this.appId}");
                throw;
            }
        }

        /// <summary>
        /// Validates the inbound request asynchronously.
        /// This method validates the JWT bearer token against the Skype/Graph
        /// OpenID Connect configuration.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns>The <see cref="RequestValidationResult"/>.</returns>
        public async Task<RequestValidationResult> ValidateInboundRequestAsync(HttpRequestMessage request)
        {
            var token = request?.Headers?.Authorization?.Parameter;
            if (string.IsNullOrWhiteSpace(token))
            {
                return new RequestValidationResult { IsValid = false };
            }

            const string authDomain = "https://api.aps.skype.com/v1/.well-known/OpenIdConfiguration";
            if (this.openIdConfiguration == null || DateTime.Now > this.prevOpenIdConfigUpdateTimestamp.Add(this.openIdConfigRefreshInterval))
            {
                this.GraphLogger.Info("Updating OpenID configuration");

                IConfigurationManager<OpenIdConnectConfiguration> configurationManager =
                    new ConfigurationManager<OpenIdConnectConfiguration>(
                        authDomain,
                        new OpenIdConnectConfigurationRetriever());
                this.openIdConfiguration = await configurationManager.GetConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

                this.prevOpenIdConfigUpdateTimestamp = DateTime.Now;
            }

            var authIssuers = new[]
            {
                "https://graph.microsoft.com",
                "https://api.botframework.com",
            };

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidIssuers = authIssuers,
                ValidAudience = this.appId,
                IssuerSigningKeys = this.openIdConfiguration.SigningKeys,
            };

            ClaimsPrincipal claimsPrincipal;
            try
            {
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                claimsPrincipal = handler.ValidateToken(token, validationParameters, out _);
            }
            catch (Exception ex)
            {
                this.GraphLogger.Error(ex, $"Failed to validate token for client: {this.appId}.");
                return new RequestValidationResult() { IsValid = false };
            }

            const string ClaimType = "http://schemas.microsoft.com/identity/claims/tenantid";
            var tenantClaim = claimsPrincipal.FindFirst(claim => claim.Type.Equals(ClaimType, StringComparison.Ordinal));

            if (string.IsNullOrEmpty(tenantClaim?.Value))
            {
                return new RequestValidationResult { IsValid = false };
            }

            request.Properties.Add(HttpConstants.HeaderNames.Tenant, tenantClaim.Value);
            return new RequestValidationResult { IsValid = true, TenantId = tenantClaim.Value };
        }
    }
}
