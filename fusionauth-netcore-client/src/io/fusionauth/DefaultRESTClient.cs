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
  class DefaultRESTClient : IRESTClient {
    public HttpClient httpClient;

    public HttpContent content;

    public string method = "GET";

    public String uri = "";

    public Dictionary<string, string> parameters = new Dictionary<string, string>();

    public Dictionary<string, string> headers = new Dictionary<string, string>();

    static DefaultRESTClient() {
      JsonConvert.DefaultSettings = () =>
        new JsonSerializerSettings {
          NullValueHandling = NullValueHandling.Ignore,
          Converters = new List<JsonConverter> {
            new StringEnumConverter(),
            new DateTimeOffsetConverter(),
            new IdentityProviderConverter()
          },
          ContractResolver = new DefaultContractResolver() 
        };
    }

    public DefaultRESTClient(string host) {
      httpClient = new HttpClient {BaseAddress = new Uri(host)};
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
     * @param body The object to be written to the request body as JSON.
     */
    public override IRESTClient withJSONBody(object body) {
      content = new StringContent(JsonConvert.SerializeObject(body), Encoding.UTF8,
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
      parameters[name] = value;
      return this;
    }

    private String getFullUri() {
      String paramString = "?";
      foreach (var (key, value) in parameters.Select(x => (x.Key, x.Value))) {
        if (!paramString.EndsWith("?")) {
          paramString += "&";
        }

        paramString += key + "=" + value;
      }

      return uri + paramString;
    }

    private Task<HttpResponseMessage> baseRequest() {
      foreach (var (key, value) in headers.Select(x => (x.Key, x.Value))) {
        httpClient.DefaultRequestHeaders.Add(key, value);
      }

      var requestUri = getFullUri();
      switch (method.ToUpper()) {
        case "GET":
          return httpClient.GetAsync(requestUri);
        case "DELETE":
          return httpClient.DeleteAsync(requestUri);
        case "PUT":
          return httpClient.PutAsync(requestUri, content);
        case "POST":
          return httpClient.PostAsync(requestUri, content);
//        case "PATCH":
//          return httpClient.PatchAsync(requestUri, content);
        default:
          throw new MissingMethodException("This REST client does not support that method. (yet?)");
      }
    }

    public override Task<ClientResponse<T>> goAsync<T>() {
      return baseRequest()
        .ContinueWith(task => {
          var clientResponse = new ClientResponse<T>();
          try {
            var result = task.Result;
            clientResponse.statusCode = (int) result.StatusCode;
            if (result.StatusCode != HttpStatusCode.OK) {
              clientResponse.errorResponse =
                JsonConvert.DeserializeObject<Errors>(result.Content.ReadAsStringAsync().Result);
            }
            else {
              clientResponse.successResponse =
                JsonConvert.DeserializeObject<T>(result.Content.ReadAsStringAsync().Result);
            }
          }
          catch (Exception e) {
            clientResponse.exception = e;
          }

          return clientResponse;
        });
    }
  }
}