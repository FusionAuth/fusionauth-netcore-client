/*
 * Copyright (c) 2018-2020, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using com.inversoft.error;
using io.fusionauth.converters;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

namespace io.fusionauth {
  internal class DefaultRESTClient : IRESTClient {
    private readonly HttpClient _httpClient;
    private readonly List<KeyValuePair<string, string>> _parameters = new List<KeyValuePair<string, string>>();
    private readonly Dictionary<string, string> _headers = new Dictionary<string, string>();
    
    private HttpContent _content;
    private string _method = "GET";
    private string _uri = "";
    
    private static readonly JsonSerializerSettings SerializerSettings = new JsonSerializerSettings
    {
        NullValueHandling = NullValueHandling.Ignore,
        Converters = new List<JsonConverter>
        {
            new StringEnumConverter(),
            new DateTimeOffsetConverter(),
            new IdentityProviderConverter()
        },
        ContractResolver = new DefaultContractResolver()
    };
    
    private static readonly ConcurrentDictionary<string, HttpClient> HttpClients = new ConcurrentDictionary<string, HttpClient>();

    public DefaultRESTClient(string host) {
        _httpClient = GetOrCreateHttpClient(host);
    }

    /**
     * Sets the authorization header using a key
     *
     * @param {string} key The value of the authorization header.
     * @returns {DefaultRESTClient}
     */
    public override IRESTClient withAuthorization(string key) {
      withHeader("Authorization", key);
      return this;
    }

    /**
     * Adds a segment to the request uri
     */
    public override IRESTClient withUriSegment(string segment) {
      if (segment == null) {
        return this;
      }

      if (_uri[_uri.Length - 1] != '/') {
        _uri += '/';
      }

      _uri += segment;
      return this;
    }

    /**
     * Adds a header to the request.
     *
     * @param key The name of the header.
     * @param value The value of the header.
     */
    public override IRESTClient withHeader(string key, string value) {
      _headers[key] = value;
      return this;
    }

    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as form data.
     */
    public override IRESTClient withFormData(FormUrlEncodedContent body)
    {
      _content = body;
      return this;
    }

    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as JSON.
     */
    public override IRESTClient withJSONBody(object body) {
      _content = new StringContent(JsonConvert.SerializeObject(body, SerializerSettings), Encoding.UTF8,
        "application/json");
      return this;
    }

    /**
     * Sets the http method for the request
     */
    public override IRESTClient withMethod(string method) {
      if (method != null) {
        this._method = method;
      }

      return this;
    }

    /**
     * Sets the uri of the request
     */
    public override IRESTClient withUri(string uri) {
      if (uri != null) {
        this._uri = uri;
      }

      return this;
    }

    /**
     * Adds parameters to the request.
     *
     * @param name The name of the parameter.
     * @param value The value of the parameter, may be a string, object or number.
     */
    public override IRESTClient withParameter(string name, string value) {
      _parameters.Add(new KeyValuePair<string, string>(name, value));
      return this;
    }

    private string GetFullUri() {
      var paramString = "?";
      foreach (var (key, value) in _parameters.Select(x => (x.Key, x.Value))) {
        if (!paramString.EndsWith("?")) {
          paramString += "&";
        }

        paramString += key + "=" + value;
      }

      return _uri + paramString;
    }

    private HttpRequestMessage BuildRequest() {
      var requestUri = GetFullUri();

      var request = new HttpRequestMessage();
      
      request.RequestUri = new Uri(requestUri, UriKind.RelativeOrAbsolute);
      
      foreach (var (key, value) in _headers.Select(x => (x.Key, x.Value))) {
          // .Add performs additional validation on the 'value' that may fail if an API key contains a '=' character.
          // - Bypass this additional validation for the Authorization header. If we find other edge cases, perhaps 
          //   we should just always use TryAddWithoutValidation unless there is a security risk. 
          if (key == "Authorization") {
              request.Headers.TryAddWithoutValidation(key, value);
          } else {
              request.Headers.Add(key, value);
          }
      }
      
      if (_content != null)
      {
          request.Content = _content;
      }

      switch (_method.ToUpper()) {
        case "GET":
          request.Method = HttpMethod.Get;
          break;
        case "DELETE": 
          request.Method = HttpMethod.Delete;
          break;
        case "PUT":
          request.Method = HttpMethod.Put;
          break;
        case "POST":
          request.Method = HttpMethod.Post;
          break;
        case "PATCH":
          request.Method = new HttpMethod("PATCH");
          break;
        default:
          throw new MissingMethodException("This REST client does not support that method. (yet?)");
      }

      return request;
    }

    public override async Task<ClientResponse<T>> goAsync<T>() {
        var clientResponse = new ClientResponse<T>();
        
        try
        {
            var request = BuildRequest();
            var result = await _httpClient.SendAsync(request).ConfigureAwait(false);
            
            clientResponse.statusCode = (int)result.StatusCode;
            
            var responseContent = await result.Content.ReadAsStringAsync().ConfigureAwait(false);
            
            if (clientResponse.statusCode >= 300)
            {
                clientResponse.errorResponse = JsonConvert.DeserializeObject<Errors>(responseContent, SerializerSettings);
            }
            else
            {
                clientResponse.successResponse = JsonConvert.DeserializeObject<T>(responseContent, SerializerSettings);
            }
        }
        catch (Exception e)
        {
            clientResponse.exception = e;
        }

        return clientResponse;
    }

    private static HttpClient GetOrCreateHttpClient(string host) => HttpClients.GetOrAdd(host, (_) => new HttpClient { BaseAddress = new Uri(host) });
  }
}