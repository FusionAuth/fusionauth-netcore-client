/*
 * Copyright (c) FusionAuth, All Rights Reserved
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
   * Models a single family member.
   *
   * @author Brian Pontarelli
   */
  public class FamilyMember {

    public IDictionary<string, object> data;

    public DateTimeOffset? insertInstant;

    public DateTimeOffset? lastUpdateInstant;

    public bool? owner;

    public FamilyRole role;

    public Guid? userId;

    public FamilyMember with(Action<FamilyMember> action) {
      action(this);
      return this;
    }
  }
}
