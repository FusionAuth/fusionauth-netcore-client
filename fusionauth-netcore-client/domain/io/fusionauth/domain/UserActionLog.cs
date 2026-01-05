/*
 * Copyright (c) 2018-2026, FusionAuth, All Rights Reserved
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
   * A log for an action that was taken on a User.
   *
   * @author Brian Pontarelli
   */
  public class UserActionLog {

    public Guid? actioneeUserId;

    public Guid? actionerUserId;

    public List<Guid> applicationIds;

    public string comment;

    public bool? emailUserOnEnd;

    public bool? endEventSent;

    public DateTimeOffset? expiry;

    public LogHistory history;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public string localizedName;

    public string localizedOption;

    public string localizedReason;

    public string name;

    public bool? notifyUserOnEnd;

    public string option;

    public string reason;

    public string reasonCode;

    public Guid? userActionId;

    public UserActionLog with(Action<UserActionLog> action) {
      action(this);
      return this;
    }
  }
}
