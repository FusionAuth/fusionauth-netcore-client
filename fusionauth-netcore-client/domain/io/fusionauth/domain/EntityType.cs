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


using System.Collections.Generic;
using System;

namespace io.fusionauth.domain {

  /**
   * Models an entity type that has a specific set of permissions. These are global objects and can be used across tenants.
   *
   * @author Brian Pontarelli
   */
  public class EntityType {

    public IDictionary<string, object> data;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public JWTConfiguration jwtConfiguration;

    public DateTimeOffset? lastUpdateInstant;

    public string name;

    public List<EntityTypePermission> permissions;

    public EntityType with(Action<EntityType> action) {
      action(this);
      return this;
    }
  }
}
