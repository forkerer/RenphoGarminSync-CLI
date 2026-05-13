using HtmlAgilityPack;
using RenphoGarminSync.Garmin.Auth.Models;
using RenphoGarminSync.Garmin.Shared;
using RenphoGarminSync.Garmin.Shared.Exceptions;
using RenphoGarminSync.Garmin.Shared.Models;
using RestSharp;
using RestSharp.Authenticators;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace RenphoGarminSync.Garmin.Auth
{
    public class GarminAuthApi : IGarminAuthApi
    {
        private readonly string _origin;
        private readonly GarminConfig _config;
        private readonly RestClient _ssoClient;
        private readonly RestClient _oauthClient;
        private readonly CookieContainer _authCookies;
        private RestClient _mfaClient;

        public GarminAuthApi(GarminConfig config)
        {
            _config = config;
            _origin = config.SSOBaseUrl;
            _authCookies = new CookieContainer();

            var ssoOptions = new RestClientOptions(config.SSOBaseUrl)
            {
                UserAgent = config.UserAgent,
                CookieContainer = _authCookies,
                FollowRedirects = false,
            };
            _ssoClient = new RestClient(ssoOptions);

            var oauthOptions = new RestClientOptions(config.ApiBaseUrl)
            {
                UserAgent = config.UserAgent,
                CookieContainer = _authCookies,
                FollowRedirects = false,
            };
            _oauthClient = new RestClient(oauthOptions);

            var mfaOptions = new RestClientOptions(_config.SSOBaseUrl)
            {
                UserAgent = config.UserAgent,
                CookieContainer = _authCookies,
            };
            _mfaClient = new RestClient(mfaOptions);
        }

        public void AddCookies(CookieCollection cookies)
        {
            _authCookies.Add(cookies);
        }

        public Task<AuthCredentials> GetConsumerCredentialsAsync()
        {
            return Task.FromResult(new AuthCredentials
            {
                ConsumerKey = _config.ConsumerKey,
                ConsumerSecret = _config.ConsumerSecret
            });
        }

        public async Task<string> GetCsrfTokenAsync()
        {
            var request = new RestRequest(GarminApiEndpoints.SSO_SIGNIN_ENDPOINT);
            AddDefaultAuthParameters(request);

            var result = await _ssoClient.ExecuteAsync(request);
            if (!result.IsSuccessful)
                throw new InvalidOperationException("Request was unsuccesful, can't retrieve csrf token");

            return GetCSRFTokenFromHtml(result.Content);
        }

        public async Task<ServiceTicketResult> GetServiceTicketAsync(string username, string password)
        {
            //await InitCookieJarIfNeededAsync();
            var csrfToken = await GetCsrfTokenAsync();
            var refererPath = new Uri(new Uri(_config.SSOBaseUrl), GarminApiEndpoints.SSO_SIGNIN_ENDPOINT).ToString();
            var request = new RestRequest(GarminApiEndpoints.SSO_SIGNIN_ENDPOINT, Method.Post)
            {
                RequestFormat = DataFormat.None
            };
            AddDefaultAuthParameters(request);
            request.AddHeader("referer", refererPath);
            request.AddHeader("NK", "NT");

            request.AddParameter("username", username);
            request.AddParameter("password", password);
            request.AddParameter("embed", "true");
            request.AddParameter("_csrf", csrfToken);

            var result = await _ssoClient.ExecuteAsync(request);
            if (result.StatusCode == HttpStatusCode.Redirect || result.StatusCode == HttpStatusCode.Found)
            {
                var redirectLocation = result.GetHeaderValue("Location");
                if (redirectLocation.Contains(GarminApiEndpoints.SSO_VERIFY_MFA))
                    return await FollowUpOnMFARedirectAsync();
            }

            if (!result.IsSuccessful)
            {
                switch (result.StatusCode)
                {
                    case HttpStatusCode.Unauthorized:
                        throw new GarminException(GarminStatusCode.InvalidCredentials, "Credentials invalid");
                    case HttpStatusCode.TooManyRequests:
                        {
                            var retryString = "later";
                            var retryAfterValue = result.GetHeaderValue("Retry-After");
                            if (!string.IsNullOrWhiteSpace(retryAfterValue))
                                retryAfterValue = $"in {retryAfterValue} seconds";

                            throw new GarminException(GarminStatusCode.TooManyRequests, $"Too many requests were placed, try again {retryString}");
                        }

                    case HttpStatusCode.Forbidden:
                        throw new GarminException(GarminStatusCode.Forbidden, "Garmin Authentication Failed. Request was Forbidden");
                    default:
                        throw new GarminException(GarminStatusCode.None, result.Content);
                }
            }

            var serviceInfo = GetServiceTicketAndUrlFromLoginResult(result.Content);
            return new ServiceTicketResult
            {
                ServiceTicket = serviceInfo.Ticket,
                ServiceUrl = serviceInfo.Url,
                MFAState = null,
            };
        }

        private async Task<ServiceTicketResult> FollowUpOnMFARedirectAsync()
        {
            var refererPath = new Uri(new Uri(_config.SSOBaseUrl), GarminApiEndpoints.SSO_SIGNIN_ENDPOINT).ToString();
            var request = new RestRequest(GarminApiEndpoints.SSO_VERIFY_MFA, Method.Get)
            {
                RequestFormat = DataFormat.None
            };
            AddDefaultAuthParameters(request);
            request.AddHeader("referer", refererPath);
            request.AddHeader("NK", "NT");

            var response = await _ssoClient.ExecuteAsync(request);
            if (!response.IsSuccessStatusCode)
                throw new GarminException(GarminStatusCode.FailedPriorToMfaUsed, response.Content);

            var csrfToken = GetCSRFTokenFromHtml(response.Content);
            var cookiesString = JsonSerializer.Serialize(_authCookies.GetAllCookies());
            return new ServiceTicketResult
            {
                ServiceTicket = null,
                MFAState = new GarminMFAState
                {
                    CookieContainer = cookiesString,
                    MFACsrfToken = csrfToken,
                    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(25),
                }
            };
        }

        public async Task<OAuth1Token> GetOAuth1TokenAsync(string serviceTicket, string serviceUrl)
        {
            var credentials = await GetConsumerCredentialsAsync();
            var authenticator = OAuth1Authenticator.ForRequestToken(credentials.ConsumerKey, credentials.ConsumerSecret);
            var request = new RestRequest(GarminApiEndpoints.OAUTH_PREAUTHORIZE_ENDPOINT)
            {
                Authenticator = authenticator
            };

            request.AddQueryParameter("ticket", serviceTicket);
            request.AddQueryParameter("login-url", serviceUrl);
            request.AddQueryParameter("accepts-mfa-tokens", "true");

            var result = await _oauthClient.ExecuteAsync(request);
            if (!result.IsSuccessful)
            {
                switch (result.StatusCode)
                {
                    case HttpStatusCode.Unauthorized:
                        throw new GarminException(GarminStatusCode.ServiceTicketInvalid, "Service ticket or url is invalid.");
                    case HttpStatusCode.TooManyRequests:
                        {
                            var retryString = "later";
                            var retryAfterValue = result.GetHeaderValue("Retry-After");
                            if (!string.IsNullOrWhiteSpace(retryAfterValue))
                                retryAfterValue = $"in {retryAfterValue} seconds";

                            throw new GarminException(GarminStatusCode.InvalidCredentials, $"Too many requests were placed, try again {retryString}");
                        }
                    case HttpStatusCode.Forbidden:
                        throw new GarminException(GarminStatusCode.Forbidden, "Garmin Authentication Failed. Request was Forbidden");
                    default:
                        throw new GarminException(GarminStatusCode.None, result.Content);
                }
            }

            var queryParams = HttpUtility.ParseQueryString(result.Content);
            var token = queryParams.Get("oauth_token");
            var secret = queryParams.Get("oauth_token_secret");

            if (string.IsNullOrWhiteSpace(token))
                throw new InvalidOperationException($"Auth appeared successful but returned OAuth1 token is null. oauth1Response: {result.Content}");

            if (string.IsNullOrWhiteSpace(secret))
                throw new InvalidOperationException($"Auth appeared successful but returned OAuth1 token secret is null. oauth1Response: {result.Content}");

            return new OAuth1Token()
            {
                Token = token,
                TokenSecret = secret,
                IssuedAt = DateTimeOffset.UtcNow
            };
        }

        public async Task<OAuth2Token> ExchangeOAuth1ForOAuth2Async(OAuth1Token oAuth1Token)
        {
            var credentials = await GetConsumerCredentialsAsync();
            var authenticator = OAuth1Authenticator.ForProtectedResource(credentials.ConsumerKey, credentials.ConsumerSecret, oAuth1Token.Token, oAuth1Token.TokenSecret);
            var request = new RestRequest(GarminApiEndpoints.OAUTH_EXCHANGE_ENDPOINT, Method.Post)
            {
                Authenticator = authenticator,
            };
            request.AddHeader(KnownHeaders.ContentType, "application/x-www-form-urlencoded");

            var result = _oauthClient.Execute(request);
            if (!result.IsSuccessful)
            {
                switch (result.StatusCode)
                {
                    case HttpStatusCode.Unauthorized:
                        throw new GarminException(GarminStatusCode.OAuth1TokenInvalid, "Credentials invalid");
                    case HttpStatusCode.TooManyRequests:
                        {
                            var retryString = "later";
                            var retryAfterValue = result.GetHeaderValue("Retry-After");
                            if (!string.IsNullOrWhiteSpace(retryAfterValue))
                                retryAfterValue = $"in {retryAfterValue} seconds";

                            throw new GarminException(GarminStatusCode.InvalidCredentials, $"Too many requests were placed, try again {retryString}");
                        }
                    case HttpStatusCode.Forbidden:
                        throw new GarminException(GarminStatusCode.Forbidden, "Garmin Authentication Failed. Request was Forbidden");
                    default:
                        throw new GarminException(GarminStatusCode.None, result.Content);
                }
            }

            var token = JsonSerializer.Deserialize<OAuth2Token>(result.Content);
            token.IssuedAt = DateTimeOffset.UtcNow;
            return token;
        }

        public async Task<ServiceTicketResult> ConfirmMFACodeAsync(string mfaCode, string csrfToken)
        {
            var request = new RestRequest(GarminApiEndpoints.SSO_VERIFY_MFA, Method.Post)
            {
                RequestFormat = DataFormat.None
            };
            AddDefaultAuthParameters(request);

            request.AddParameter("mfa-code", mfaCode);
            request.AddParameter("fromPage", "setupEnterMfaCode");
            request.AddParameter("embed", "true");
            request.AddParameter("_csrf", csrfToken);

            var result = await _mfaClient.ExecuteAsync(request);
            if (!result.IsSuccessful)
            {
                if (result.StatusCode == HttpStatusCode.Forbidden)
                {
                    if (result.Content.Contains("error code: 1020"))
                        throw new GarminException(GarminStatusCode.Forbidden, "Garmin Authentication Failed. Blocked by CloudFlare");

                    throw new GarminException(GarminStatusCode.InvalidMfaCode, "MFA Code rejected by Garmin");
                }

                throw new GarminException(GarminStatusCode.None, result.Content);
            }

            var serviceInfo = GetServiceTicketAndUrlFromLoginResult(result.Content);
            return new ServiceTicketResult
            {
                ServiceTicket = serviceInfo.Ticket,
                ServiceUrl = serviceInfo.Url,
                MFAState = null,
            };
        }

        private (string Ticket, string Url) GetServiceTicketAndUrlFromLoginResult(string htmlContent)
        {
            // Try to find the full post login ServiceTicket
            var ticketRegex = new Regex("embed\\?.*ticket=(?<ticket>[^\"]+)\"");
            var ticketMatch = ticketRegex.Match(htmlContent);
            if (!ticketMatch.Success)
                throw new GarminException(GarminStatusCode.AuthAppearedSuccessful, "Auth appeared successful but failed to find regex match for service ticket.");

            var ticket = ticketMatch.Groups.GetValueOrDefault("ticket").Value;
            if (string.IsNullOrWhiteSpace(ticket))
                throw new GarminException(GarminStatusCode.AuthAppearedSuccessful, "Auth appeared successful, and found service ticket, but ticket was null or empty.");

            var serviceRegex = new Regex("service_url\\s*=\\s*\"(?<serviceUrl>[^\"]+)\"");
            var serviceMatch = serviceRegex.Match(htmlContent);
            if (!serviceMatch.Success)
                throw new GarminException(GarminStatusCode.AuthAppearedSuccessful, "Auth appeared successful but failed to find regex match for service url.");

            var serviceUrl = serviceMatch.Groups.GetValueOrDefault("serviceUrl").Value;
            if (string.IsNullOrWhiteSpace(serviceUrl))
                throw new GarminException(GarminStatusCode.AuthAppearedSuccessful, "Auth appeared successful, and found service ticket, but service url was null or empty.");

            serviceUrl = Regex.Unescape(serviceUrl);
            return (ticket, serviceUrl);
        }

        private void AddDefaultAuthParameters(RestRequest request)
        {
            var embedUrl = new Uri(new Uri(_config.SSOBaseUrl), GarminApiEndpoints.SSO_EMBED_ENDPOINT).ToString();
            var serviceUrl = $"{embedUrl}?accepts-mfa-tokens=true";

            request.AddQueryParameter("id", "gauth-widget");
            request.AddQueryParameter("embedWidget", "true");
            request.AddQueryParameter("gauthHost", embedUrl);
            request.AddQueryParameter("service", serviceUrl);
            request.AddQueryParameter("source", embedUrl);
            request.AddQueryParameter("redirectAfterAccountLoginUrl", embedUrl);
            request.AddQueryParameter("redirectAfterAccountCreationUrl", embedUrl);

            request.AddHeader("origin", _origin);
        }

        private string GetCSRFTokenFromHtml(string htmlContent)
        {
            var htmlDoc = new HtmlDocument();
            htmlDoc.LoadHtml(htmlContent);

            var csrfInput = htmlDoc.DocumentNode.SelectSingleNode("//input[@name='_csrf']");
            if (csrfInput is null)
                throw new InvalidOperationException("Couldn't find csrf input node");

            var csrfValue = csrfInput.GetAttributeValue<string>("value", string.Empty);
            if (string.IsNullOrWhiteSpace(csrfValue))
                throw new InvalidOperationException("Null or empty csrf token");

            return csrfValue;
        }
    }
}
