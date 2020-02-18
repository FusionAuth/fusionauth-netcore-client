/*
 * Copyright (c) 2018, FusionAuth, All Rights Reserved
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


using io.fusionauth.domain.@event;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain {

  /**
   * A server where events are sent. This includes user action events and any other events sent by FusionAuth.
   *
   * @author Brian Pontarelli
   */
  public class Webhook {

    public List<Guid> applicationIds;

    public int? connectTimeout;

    public Dictionary<string, object> data;

    public string description;

    public Dictionary<EventType, bool> @eventsEnabled;

    public bool? global;

    public HTTPHeaders headers;

    public string httpAuthenticationPassword;

    public string httpAuthenticationUsername;

    public Guid? id;

    public int? readTimeout;

    public string sslCertificate;

    public string url;

    public Webhook with(Action<Webhook> action) {
      action(this);
      return this;
    }
  }
}
