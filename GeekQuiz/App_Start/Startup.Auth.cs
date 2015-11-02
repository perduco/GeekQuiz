// ----------------------------------------------------------------------------------
// Microsoft Developer & Platform Evangelism
// 
// Copyright (c) Microsoft Corporation. All rights reserved.
// 
// THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
// EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES 
// OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
// ----------------------------------------------------------------------------------
// The example companies, organizations, products, domain names,
// e-mail addresses, logos, people, places, and events depicted
// herein are fictitious.  No association with any real company,
// organization, product, domain name, email address, logo, person,
// places, or events is intended or should be inferred.
// ----------------------------------------------------------------------------------

using GeekQuiz.App_Start;
using GeekQuiz.Models;
using GeekQuiz.Policies;
using GeekQuiz.Utils;
using Microsoft.AspNet.Identity;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.Globalization;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Web;

namespace GeekQuiz
{
    public static class IdentityExtensions
    {
        public static bool IsExternalUser(this IIdentity identity)
        {
            var ci = identity as ClaimsIdentity;
            if (ci != null && ci.IsAuthenticated == true)
            {
                var value = ci.FindFirstValue(ClaimTypes.Sid);
                if (value != null && value == "Office365")
                {
                    return true;
                }
            }

            return false;
        }
    }

    public partial class Startup
    {
        //
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        // The App Key is a credential used to authenticate the application to Azure AD.  Azure AD supports password and certificate credentials.
        // The Metadata Address is used by the application to retrieve the signing keys used by Azure AD.
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Authority is the sign-in URL of the tenant.
        // The Post Logout Redirect Uri is the URL where the user will be redirected after they sign out.
        //
        private static string clientIdAAD = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string aadInstanceAAD = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenantAAD = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string postLogoutRedirectUriAAD = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

        public static readonly string AuthorityAAD = String.Format(CultureInfo.InvariantCulture, aadInstanceAAD, tenantAAD);

        // This is the resource ID of the AAD Graph API.  We'll need this to request a token to call the Graph API.
//        string graphResourceId = ConfigurationManager.AppSettings["ida:GraphResourceId"];

        private const string OIDCMetadataSuffix = "/.well-known/openid-configuration";
        public const string AcrClaimType = "http://schemas.microsoft.com/claims/authnclassreference";
        public const string TenantClaimType = "http://schemas.microsoft.com/identity/claims/tenantid";
        public const string PolicyKey = "b2cpolicy";

        private static string clientIdB2C = ConfigurationManager.AppSettings["b2c:ClientId"];
        private static string aadInstanceB2C = ConfigurationManager.AppSettings["b2c:AADInstance"];
        private static string tenantB2C = ConfigurationManager.AppSettings["b2c:Tenant"];
        private static string postLogoutRedirectUriB2C = ConfigurationManager.AppSettings["b2c:PostLogoutRedirectUri"];

        // B2C policy identifiers
        public static string SignUpPolicyId = ConfigurationManager.AppSettings["b2c:SignUpPolicyId"];
        public static string SignInPolicyId = ConfigurationManager.AppSettings["b2c:SignInPolicyId"];
        //public static string ResetPolicyId = ConfigurationManager.AppSettings["b2c:PasswordResetPolicyId"];
        public static string ProfilePolicyId = ConfigurationManager.AppSettings["b2c:UserProfilePolicyId"];


        public static readonly string AuthorityB2C = String.Format(CultureInfo.InvariantCulture, aadInstanceB2C, tenantB2C, OIDCMetadataSuffix);

        private Task AuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            return Task.FromResult(0);
        }

        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationRoleManager>(ApplicationRoleManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            // Use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            OpenIdConnectAuthenticationOptions b2coptions = new OpenIdConnectAuthenticationOptions
            {
                // Standard OWIN OIDC parameters
                Authority = String.Format(aadInstanceB2C, tenantB2C),
                ClientId = clientIdB2C,
                RedirectUri = postLogoutRedirectUriB2C,
                PostLogoutRedirectUri = postLogoutRedirectUriB2C,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = AuthenticationFailed,
                },

                // Required for AAD B2C
                Scope = "openid",
                ConfigurationManager = new B2CConfigurationManager(
                    String.Format(CultureInfo.InvariantCulture, aadInstanceB2C + "{1}", tenantB2C, OIDCMetadataSuffix)),

                //ConfigurationManager = new PolicyConfigurationManager(AuthorityB2C,
                //    new string[] { SignUpPolicyId, SignInPolicyId/*, ProfilePolicyId*/ }),

                // Optional - used for displaying the user's name in the navigation bar when signed in.
                TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                {
                    NameClaimType = "name",
                },

                AuthenticationType = "B2C"
                ,
                ProtocolValidator = new OpenIdConnectProtocolValidator { RequireNonce = false }
            };

            // Required for AAD B2C
            app.Use(typeof(B2COpenIdConnectAuthenticationMiddleware), app, b2coptions);

//            app.UseOpenIdConnectAuthentication(b2coptions);

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientIdAAD,
                    Authority = AuthorityAAD,
                    PostLogoutRedirectUri = postLogoutRedirectUriAAD,

                    //TokenValidationParameters = new TokenValidationParameters
                    //{
                    //    ValidateIssuer = false,
                    //},
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        //
                        // If there is a code in the OpenID Connect response, redeem it for an access token and refresh token, and store those away.
                        //
                        //AuthorizationCodeReceived = (context) =>
                        //{
                        //    var code = context.Code;

                        //    ClientCredential credential = new ClientCredential(clientId, appKey);
                        //    string userObjectID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
                        //    AuthenticationContext authContext = new AuthenticationContext(Authority, new NaiveSessionCache(userObjectID));
                        //    AuthenticationResult result = authContext.AcquireTokenByAuthorizationCode(code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, graphResourceId);

                        //    return Task.FromResult(0);
                        //},
                        //RedirectToIdentityProvider = (context) =>
                        //{

                        //    if (context.Request.Path.Value == "/Account/ExternalLogin" || (context.Request.Path.Value == "/Account/LogOff" && context.Request.User.Identity.IsExternalUser()))
                        //    {
                        //        // This ensures that the address used for sign in and sign out is picked up dynamically from the request
                        //        // this allows you to deploy your app (to Azure Web Sites, for example)without having to change settings
                        //        // Remember that the base URL of the address used here must be provisioned in Azure AD beforehand.
                        //        string appBaseUrl = context.Request.Scheme + "://" + context.Request.Host + context.Request.PathBase;
                        //        context.ProtocolMessage.RedirectUri = appBaseUrl + "/";
                        //        context.ProtocolMessage.PostLogoutRedirectUri = appBaseUrl;
                        //    }
                        //    else
                        //    {
                        //        //This is to avoid being redirected to the microsoft login page when deep linking and not logged in 
                        //        context.State = Microsoft.Owin.Security.Notifications.NotificationResultState.Skipped;
                        //        context.HandleResponse();
                        //    }
                        //    return Task.FromResult(0);
                        //},
                        AuthenticationFailed = context =>
                        {
                            context.HandleResponse();
                            context.Response.Redirect("/Home/Error?message=" + context.Exception.Message); 
                            return Task.FromResult(0);
                        }

                    },
                    Description = new AuthenticationDescription() { Caption = "AAD" },
                    AuthenticationType = "AAD"

                });

            // Enable the application to use a cookie to store information for the signed in user
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login")
            });

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            //app.UseGoogleAuthentication();
        }
    }
}