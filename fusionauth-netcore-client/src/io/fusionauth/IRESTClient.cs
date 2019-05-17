using System;
using System.Threading.Tasks;

namespace io.fusionauth {
  public abstract class IRESTClient {
    /**
     * Sets the authorization header using a key
     *
     * @param {string} key The value of the authorization header.
     * @returns {IRESTClient}
     */
    public abstract IRESTClient withAuthorization(string key);

    /**
     * Adds a segment to the request uri
     */
    public abstract IRESTClient withUriSegment(string segment);

    public IRESTClient withUriSegment(object segment) {
      if (segment == null) {
        return this;
      }

      return withUriSegment(segment.ToString());
    }

    /**
     * Adds a header to the request.
     *
     * @param key The name of the header.
     * @param value The value of the header.
     */
    public abstract IRESTClient withHeader(string key, string value);

    public IRESTClient withHeader(string key, object value) {
      if (value == null) {
        return this;
      }
      
      return withHeader(key, value.ToString());
    }

    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as JSON.
     */
    public abstract IRESTClient withJSONBody(Object body);

    /**
     * Sets the http method for the request
     */
    public abstract IRESTClient withMethod(string method);

    /**
     * Sets the uri of the request
     */
    public abstract IRESTClient withUri(string uri);

    /**
     * Adds parameters to the request.
     *
     * @param name The name of the parameter.
     * @param value The value of the parameter, may be a string, object or number.
     */
    public abstract IRESTClient withParameter(string name, string value);

    public IRESTClient withParameter(string name, bool value) {
      return withParameter(name, value ? "true" : "false");
    }

    public IRESTClient withParameter(string name, object value) {
      if (value == null) {
        return this;
      }
      
      return withParameter(name, value.ToString());
    }

    /**
     * Run the request and return a promise. This promise will resolve if the request is successful
     * and reject otherwise.
     */
    public ClientResponse<T> go<T>() {
      return goAsync<T>().Result;
    }

    /**
     * 
     */
    public abstract Task<ClientResponse<T>> goAsync<T>();
  }
}