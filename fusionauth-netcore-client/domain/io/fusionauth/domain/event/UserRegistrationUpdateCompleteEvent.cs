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
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.@event {

  /**
   * Models the User Update Registration Event.
   * <p>
   * This is different than user.registration.update in that it is sent after this event completes, this cannot be transactional.
   *
   * @author Daniel DeGroff
   */
  public class UserRegistrationUpdateCompleteEvent: BaseEvent {

    public Guid? applicationId;

    public UserRegistration original;

    public UserRegistration registration;

    public User user;

    public UserRegistrationUpdateCompleteEvent with(Action<UserRegistrationUpdateCompleteEvent> action) {
      action(this);
      return this;
    }
  }
}
