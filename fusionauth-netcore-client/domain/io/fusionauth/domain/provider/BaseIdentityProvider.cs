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


using io.fusionauth.domain;
using io.fusionauth.converters.helpers;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.provider {

  // Do not require a setter for 'type', it is defined by the concrete class and is not mutable
  public class BaseIdentityProvider<D>: Enableable, IdentityProvider {

    public Dictionary<Guid, D> applicationConfiguration;

    public Dictionary<string, object> data;

    public bool? debug;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public LambdaConfiguration lambdaConfiguration;

    public DateTimeOffset? lastUpdateInstant;

    public string name;

    public IdentityProviderType type;
  }
}
