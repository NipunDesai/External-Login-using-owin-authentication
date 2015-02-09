using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Owin;
using FacebookLogin.Models;

namespace FacebookLogin
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "1615790648639864",
            //   appSecret: "22145d34bf9436d146bd3ebcbf45ddd8");

    
            //var facebookOptions = new FacebookAuthenticationOptions()
            //{
            //    AppId = "1615790648639864",
            //    AppSecret = "22145d34bf9436d146bd3ebcbf45ddd8"
            //};
            //facebookOptions.Scope.Add("email");
            //app.UseFacebookAuthentication(facebookOptions);

            var facebookAuthenticationOptions = new FacebookAuthenticationOptions();

            facebookAuthenticationOptions.Scope.Add("email");

            facebookAuthenticationOptions.AppId = "1615790648639864";
            facebookAuthenticationOptions.AppSecret = "22145d34bf9436d146bd3ebcbf45ddd8";
            facebookAuthenticationOptions.Provider = new FacebookAuthenticationProvider()
              {
                  OnAuthenticated = async context =>
                  {
                      context.Identity.AddClaim(new System.Security.Claims.Claim("FacebookAccessToken", context.AccessToken));
                      foreach (var claim in context.User)
                      {
                          var claimType = string.Format("urn:facebook:{0}", claim.Key);
                          string claimValue = claim.Value.ToString();
                          if (!context.Identity.HasClaim(claimType, claimValue))
                              context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Facebook"));

                      }

                  }
              };

            facebookAuthenticationOptions.SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie;
            app.UseFacebookAuthentication(facebookAuthenticationOptions);


            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "296305148373-oef8llus5colp44j15n2dmknb7c2eu3h.apps.googleusercontent.com",
                ClientSecret = "QW7JdMsn9AtEGaWtB6CpQL3d"
            });

            //app.UseGoogleAuthentication(
            //clientId: "296305148373-id7dui533e3pf7b4fhb1chhe1tjcj9ks.apps.googleusercontent.com",
            //clientSecret: "YjflI3CdIry25d5pQIm9bBK2");
        }
    }
}