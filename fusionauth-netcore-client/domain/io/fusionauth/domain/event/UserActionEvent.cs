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


using io.fusionauth.domain.email;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.@event {

  /**
   * Models the user action event (and can be converted to JSON).
   *
   * @author Brian Pontarelli
   */
  public class UserActionEvent: BaseEvent {

    public string action;

    public Guid? actionId;

    public Guid? actioneeUserId;

    public Guid? actionerUserId;

    public List<Guid> applicationIds;

    public string comment;

    public Email email;

    public bool? emailedUser;

    public DateTimeOffset? expiry;

    public string localizedAction;

    public string localizedDuration;

    public string localizedOption;

    public string localizedReason;

    public bool? notifyUser;

    public string option;

    public UserActionPhase phase;

    public string reason;

    public string reasonCode;

    public UserActionEvent with(Action<UserActionEvent> action) {
      action(this);
      return this;
    }
  }
}
