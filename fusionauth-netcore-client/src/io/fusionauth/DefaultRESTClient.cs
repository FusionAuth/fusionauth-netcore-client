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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using com.inversoft.error;
using io.fusionauth.converters;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

namespace io.fusionauth {
  public class DefaultRESTClient : IRESTClient {
    public HttpClient httpClient;

    public HttpContent content;

    public string method = "GET";

    public String uri = "";

    public List<KeyValuePair<string, string>> parameters = new List<KeyValuePair<string, string>>();

    public Dictionary<string, string> headers = new Dictionary<string, string>();

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

    public DefaultRESTClient(string host) {
      httpClient = new HttpClient {BaseAddress = new Uri(host)};
    }

    public DefaultRESTClient(HttpClient httpClient) {
      httpClient = httpClient;
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

      if (uri[uri.Length - 1] != '/') {
        uri += '/';
      }

      uri = uri + segment;
      return this;
    }

    /**
     * Adds a header to the request.
     *
     * @param key The name of the header.
     * @param value The value of the header.
     */
    public override IRESTClient withHeader(string key, string value) {
      headers[key] = value;
      return this;
    }

    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as form data.
     */
    public override IRESTClient withFormData(FormUrlEncodedContent body)
    {
      content = body;
      return this;
    }

    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as JSON.
     */
    public override IRESTClient withJSONBody(object body) {
      content = new StringContent(JsonConvert.SerializeObject(body, SerializerSettings), Encoding.UTF8,
        "application/json");
      return this;
    }

    /**
     * Sets the http method for the request
     */
    public override IRESTClient withMethod(string method) {
      if (method != null) {
        this.method = method;
      }

      return this;
    }

    /**
     * Sets the uri of the request
     */
    public override IRESTClient withUri(string uri) {
      if (uri != null) {
        this.uri = uri;
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
      parameters.Add(new KeyValuePair<string, string>(name, value));
      return this;
    }

    private string getFullUri() {
        if (!parameters.Any())
        {
            return uri;
        }

        var encodedParameters = parameters.Select(p => $"{WebUtility.UrlEncode(p.Key)}={WebUtility.UrlEncode(p.Value)}");

        var queryString = string.Join("&", encodedParameters);
        
        return $"{uri}?{queryString}";
    }

    private Task<HttpResponseMessage> baseRequest() {
      foreach (var (key, value) in headers.Select(x => (x.Key, x.Value))) {
        // .Add performs additional validation on the 'value' that may fail if an API key contains a '=' character.
        // - Bypass this additional validation for the Authorization header. If we find other edge cases, perhaps 
        //   we should just always use TryAddWithoutValidation unless there is a security risk. 
        if (key == "Authorization") {
          httpClient.DefaultRequestHeaders.TryAddWithoutValidation(key, value);
        } else {
          httpClient.DefaultRequestHeaders.Add(key, value);
        }
      }

      var requestUri = getFullUri();
      switch (method.ToUpper()) {
        case "GET":
          return httpClient.GetAsync(requestUri);
        case "DELETE":
          if (content != null) {
            var request = new HttpRequestMessage(HttpMethod.Delete, requestUri);
            request.Content = content;
            return httpClient.SendAsync(request);
          } else {
            return httpClient.DeleteAsync(requestUri);
          }
        case "PUT":
          return httpClient.PutAsync(requestUri, content);
        case "POST":
          return httpClient.PostAsync(requestUri, content);
        case "PATCH":
          var patchRequest = new HttpRequestMessage();
          patchRequest.Method = new HttpMethod("PATCH");
          patchRequest.Content = content;
          patchRequest.RequestUri = new Uri(requestUri, UriKind.RelativeOrAbsolute);
          return httpClient.SendAsync(patchRequest);
        default:
          throw new MissingMethodException("This REST client does not support that method. (yet?)");
      }
    }

    public override Task<ClientResponse<T>> goAsync<T>() {
      return baseRequest()
        .ContinueWith(task => {
      var clientResponse = new ClientResponse<T>();
      try
      {
            var result = task.Result;
        clientResponse.statusCode = (int)result.StatusCode;
            if (clientResponse.statusCode >= 300) {
              clientResponse.errorResponse =
                JsonConvert.DeserializeObject<Errors>(result.Content.ReadAsStringAsync().Result, SerializerSettings);
        }
            else {
              clientResponse.successResponse =
                JsonConvert.DeserializeObject<T>(result.Content.ReadAsStringAsync().Result, SerializerSettings);
        }
      }
      catch (Exception e)
      {
        clientResponse.exception = e;
      }

      return clientResponse;
        });
    }
  }
}