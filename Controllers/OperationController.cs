using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using Newtonsoft.Json.Linq;

namespace GatewayProxy.Controllers
{
    public class OperationController : ApiController
    {
        public const string JwtIssuer = "https://geomaster.azurewebsites.windows.net/";

        public const string JwtAudience = "https://management.core.windows.net/";
        const string VersionSuffix = "-privatepreview";
        const string CurrentGeoUri = "https://geomaster.antdir0.antares-test.windows-int.net:444/";
        const string IntAppGeoUri = "https://geomaster.ant-intapp-admin.windows-int.net:444/";

        [HttpGet, HttpPost, HttpPut, HttpHead, HttpPatch, HttpOptions, HttpDelete]
        public async Task<HttpResponseMessage> Invoke(HttpRequestMessage requestMessage)
        {
            try
            {
                return await InvokeInternal(requestMessage);
            }
            catch (Exception ex)
            {
                var response = new HttpResponseMessage(HttpStatusCode.InternalServerError);
                var json = new JObject();
                json["code"] = (int)HttpStatusCode.InternalServerError;
                json["message"] = ex.ToString();
                response.Content = new StringContent(json.ToString(), Encoding.UTF8, "application/json");
                return response;
            }
        }

        private async Task<HttpResponseMessage> InvokeInternal(HttpRequestMessage requestMessage)
        {
            var authotization = requestMessage.Headers.Authorization;
            if (authotization == null || String.IsNullOrEmpty(authotization.Scheme) || String.IsNullOrEmpty(authotization.Parameter))
            {
                throw new InvalidOperationException("Authorization header is missing!");
            }

            if (!authotization.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Authorization header has an invalid '" + authotization.Scheme + "' scheme!");
            }

            var jwt = authotization.Parameter;
            var claims = ValidateJwt(jwt, new[] { Utils.GetIssuerCertificate() });
            var aud = claims.FirstOrDefault(c => c.Type == "aud");
            if (aud == null || String.IsNullOrEmpty(aud.Value))
            {
                throw new InvalidOperationException("Audience claim is missing!");
            }

            var requestUri = requestMessage.RequestUri;
            var client = new HttpClient();
            requestMessage.RequestUri = new Uri(new Uri(aud.Value), requestUri.PathAndQuery);
            requestMessage.Headers.Host = null;
            requestMessage.Headers.Authorization = authotization;

            // These header is defined by client/server policy.  Since we are forwarding, 
            // it does not apply to the communication from this node to next.   Remove them.
            RemoveConnectionHeaders(requestMessage.Headers);

            // This is to work around Server's side request message always has Content.
            // For non-null content, if we try to forward wiht say GET verb, HttpClient will fail protocol exception.
            // Workaround is to null out in such as.  Checking ContentType seems least disruptive.
            if (requestMessage.Content != null && requestMessage.Content.Headers.ContentType == null)
            {
                requestMessage.Content = null;
            }

            try
            {
                var response = await client.SendAsync(requestMessage);

                // These header is defined by client/server policy.  Since we are forwarding, 
                // it does not apply to the communication from this node to next.   Remove them.
                RemoveConnectionHeaders(response.Headers);

                Utils.WriteLine("{0} {1} {2}", requestMessage.Method, requestMessage.RequestUri, response.StatusCode);

                return response;
            }
            catch (Exception ex)
            {
                Utils.WriteLine("{0} {1} {2}", requestMessage.Method, requestMessage.RequestUri, ex);
                throw;
            }
        }

        private static void RemoveConnectionHeaders(HttpHeaders headers)
        {
            var connection = headers is HttpRequestHeaders ? ((HttpRequestHeaders)headers).Connection : ((HttpResponseHeaders)headers).Connection;
            foreach (var name in connection)
            {
                headers.Remove(name);
            }
            headers.Remove("Connection");
        }

        static IEnumerable<Claim> ValidateJwt(string jwt, X509Certificate2[] issuerCers)
        {
            var parameters = new TokenValidationParameters();
            parameters.CertificateValidator = X509CertificateValidator.None;
            parameters.ValidateAudience = false;
            //parameters.ValidAudience = JwtAudience;
            parameters.ValidateIssuer = true;
            parameters.ValidIssuer = JwtIssuer;
            parameters.ValidateLifetime = true;
            parameters.ClockSkew = TimeSpan.FromMinutes(5);

            var signingTokens = new List<SecurityToken>();
            signingTokens.AddRange(issuerCers.Select(cert => new X509SecurityToken(cert)));
            parameters.IssuerSigningTokens = signingTokens;

            var handler = new JwtSecurityTokenHandler();
            SecurityToken result = null;
            var principal = handler.ValidateToken(jwt, parameters, out result);
            return principal.Claims;
        }
    }
}