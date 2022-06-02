/*
 * Copyright (c) 2018-2022, FusionAuth, All Rights Reserved
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


using io.fusionauth.domain;
using io.fusionauth.jwt.domain;
using Newtonsoft.Json;
using System.Collections.Generic;
using System;

namespace io.fusionauth.jwks.domain {

  /**
   * A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 JSON Web Key (JWK)
   * Section 4</a> and <a href="https://tools.ietf.org/html/rfc7518">RFC 7518 JSON Web Algorithms (JWA)</a>.
   *
   * @author Daniel DeGroff
   */
  public class JSONWebKey {

    public Algorithm alg;

    public string crv;

    public string d;

    public string dp;

    public string dq;

    public string e;

    public string kid;

    public KeyType? kty;

    public string n;

    public dynamic this[string claim] {
      get => other[claim];
      set => other[claim] = value;
    }

    [JsonExtensionData]
    private readonly Dictionary<string, dynamic> other = new Dictionary<string, dynamic>();

    public string p;

    public string q;

    public string qi;

    public string use;

    public string x;

    public List<string> x5c;

    public string x5t;

    public string x5t_S256;

    public string y;

    public JSONWebKey with(Action<JSONWebKey> action) {
      action(this);
      return this;
    }
  }
}
