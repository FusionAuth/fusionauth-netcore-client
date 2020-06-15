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
using System.Net.Http;
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
     * @param body The object to be written to the request body as form data.
     */
    public abstract IRESTClient withFormData(FormUrlEncodedContent body);

    /**
     * Sets the body of the client request.
     *
     * @param body The object to be written to the request body as JSON.
     */
    public abstract IRESTClient withJSONBody(object body);

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

    public IRESTClient withParameter<T>(string name, IEnumerable<T> value) {
      if (value == null) {
        return this;
      }

      return value.Aggregate(this, (current, val) => current.withParameter(name, val));
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