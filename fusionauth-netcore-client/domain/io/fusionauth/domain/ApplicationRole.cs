/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain
{

  /**
   * A role given to a user for a specific application.
   *
   * @author Seth Musselman
   */
  public class ApplicationRole {

    public string description;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public bool? isDefault;

    public bool? isSuperRole;

    public DateTimeOffset? lastUpdateInstant;

    public string name;

    public ApplicationRole with(Action<ApplicationRole> action) {
      action(this);
      return this;
    }
  }
}
