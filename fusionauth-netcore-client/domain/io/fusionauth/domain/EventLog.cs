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
   * Event log used internally by FusionAuth to help developers debug hooks, Webhooks, email templates, etc.
   *
   * @author Brian Pontarelli
   */
  public class EventLog {

    public long? id;

    public DateTimeOffset? insertInstant;

    public string message;

    public EventLogType type;

    public EventLog with(Action<EventLog> action) {
      action(this);
      return this;
    }
  }
}
