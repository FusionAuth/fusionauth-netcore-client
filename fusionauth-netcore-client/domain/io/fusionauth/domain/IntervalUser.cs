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
   * A user over an period (for daily and monthly active user calculations).
   *
   * @author Brian Pontarelli
   */
  public class IntervalUser {

    public Guid? applicationId;

    public int? period;

    public Guid? userId;

    public IntervalUser with(Action<IntervalUser> action) {
      action(this);
      return this;
    }
  }
}
