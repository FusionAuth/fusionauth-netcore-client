using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using com.inversoft.error;
using io.fusionauth.converters;
using io.fusionauth.domain;
using io.fusionauth.domain.api;
using io.fusionauth.domain.api.user;
using io.fusionauth.domain.@email;
using io.fusionauth.domain.@event;
using io.fusionauth.domain.provider;
using io.fusionauth.jwt.domain;
using Microsoft.VisualStudio.TestPlatform.Common.Utilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using NUnit.Framework;

namespace io.fusionauth {
  public class TestBuilder {
    public string apiKey = Environment.GetEnvironmentVariable("FUSIONAUTH_API_KEY") ??
                           "bf69486b-4733-4470-a592-f1bfce7af580";

    public string fusionauthUrl = Environment.GetEnvironmentVariable("FUSIONAUTH_URL") ?? "http://localhost:9011";

    public static readonly Guid ApplicationId = new Guid("4eedf18a-9360-40f6-a36c-88269ed5ec55");

    public const string emailAddress = "csharpclient@fusionauth.io";

    public Application application;

    public FusionAuthSyncClient client;

    public string token;

    public User user;

    public UserAction userAction;

    public UserActionLog userActionLog;

    public TestBuilder() {
      client = new FusionAuthSyncClient(apiKey, fusionauthUrl);
    }

    public FusionAuthSyncClient newClientWithTenantId(Guid tenantId) {
      return new FusionAuthSyncClient(apiKey, fusionauthUrl, tenantId.ToString());
    }

    public TestBuilder assertSuccess<T>(ClientResponse<T> response) {
      var message = response.exception == null ? "No Errors" : response.exception.ToString();
      Assert.IsNull(response.exception);
      Assert.AreEqual(200, response.statusCode,
        response.errorResponse != null ? JsonConvert.SerializeObject(response.errorResponse) : message);
      Assert.IsNull(response.errorResponse);

      return this;
    }

    public TestBuilder assertStatusCode<T>(ClientResponse<T> response, int expectedCode) {
      Assert.AreEqual(expectedCode, response.statusCode,
        response.errorResponse != null ? response.errorResponse.ToString() : "No errors");
      Assert.IsNull(response.exception);
      if (expectedCode == 400) {
        Assert.IsNotNull(response.errorResponse);
      }
      else {
        Assert.IsNull(response.errorResponse);
      }

      Assert.IsNull(response.successResponse);

      return this;
    }

    public TestBuilder assertMissing<T>(ClientResponse<T> response) {
      Assert.AreEqual(404, response.statusCode,
        response.errorResponse != null ? response.errorResponse.ToString() : "No errors");
      Assert.IsNull(response.exception);
      Assert.IsNull(response.errorResponse);
      Assert.IsNull(response.successResponse);

      return this;
    }

    public TestBuilder callClient(Action<FusionAuthSyncClient> action) {
      action(client);
      return this;
    }

    public TestBuilder createUser() {
      var retrieveResponse = client.RetrieveUserByEmail(emailAddress);
      if (retrieveResponse.WasSuccessful()) {
        assertSuccess(client.DeleteUser(retrieveResponse.successResponse.user.id));
      }

      var newUser = new User()
        .with(u => u.email = emailAddress)
        .with(u => u.username = "csharpclient")
        .with(u => u.password = "password");

      var newRegistration = new UserRegistration()
        .with(r => r.applicationId = ApplicationId)
        .with(r => r.username = "csharpclient");

      var response = client.Register(null, new RegistrationRequest().with(rr => rr.user = newUser)
        .with(rr => rr.registration = newRegistration)
        .with(rr => rr.sendSetPasswordEmail = false)
        .with(rr => rr.skipVerification = true));
      assertSuccess(response);
      Assert.AreEqual(newUser.username, response.successResponse.user.username);

      user = response.successResponse.user;
      return this;
    }

    public TestBuilder createUserAction(string actionName, bool isTemporal) {
      var retrieveResponse = client.RetrieveUserActions();
      assertSuccess(retrieveResponse);
      if (retrieveResponse.successResponse.userActions != null) {
        foreach (UserAction userAction in retrieveResponse.successResponse.userActions) {
          if (userAction.name.Equals(actionName)) {
            assertSuccess(client.DeleteUserAction(userAction.id));
          }
        }
      }

      var request = new UserActionRequest() {
        userAction = new UserAction() {
          name = actionName,
          temporal = isTemporal
        }
      };
      var response = client.CreateUserAction(null, request);
      assertSuccess(response);
      this.userAction = response.successResponse.userAction;
      return this;
    }

    public TestBuilder actionUser() {
      var actionRequest = new ActionRequest() {
        broadcast = false,
        action = new ActionData() {
          actionerUserId = this.user.id,
          actioneeUserId = this.user.id,
          expiry = (this.userAction.temporal.Value) ? DateTimeOffset.Now.AddHours(1) : (DateTimeOffset?) null,
          userActionId = this.userAction.id
        }
      };
      var actionResponse = client.ActionUser(actionRequest);
      assertSuccess(actionResponse);
      this.userActionLog = actionResponse.successResponse.action;
      return this;
    }

    public TestBuilder login() {
      var response = client.Login(new LoginRequest()
        .with(lr => lr.applicationId = application.id)
        .with(lr => lr.loginId = user.email)
        .with(lr => lr.password = "password"));
      assertSuccess(response);

      token = response.successResponse.token;
      user = response.successResponse.user;
      return this;
    }

    public TestBuilder updateApplication(Application application) {
      var response = client.UpdateApplication(ApplicationId, new ApplicationRequest()
        .with(ar => ar.application = application));
      assertSuccess(response);

      this.application = response.successResponse.application;
      return this;
    }

    public TestBuilder createApplication() {
      var retrieveResponse = client.RetrieveApplication(ApplicationId);
      if (retrieveResponse.WasSuccessful()) {
        assertSuccess(client.DeleteApplication(ApplicationId));
      }

      var application = new Application()
        .with(app => app.name = "CSharp Client Test");
      var response = client.CreateApplication(ApplicationId,
        new ApplicationRequest()
          .with(ar => ar.application = new Application()
            .with(app => app.name = "CSharp Client Test")));

      assertSuccess(response);
      Assert.AreEqual(application.name, response.successResponse.application.name);

      this.application = response.successResponse.application;
      return this;
    }
  }

  [TestFixture]
  public class FusionAuthClientTest {
    private TestBuilder test;

    [SetUp]
    public void initialize() {
      test = new TestBuilder();
    }

    [Test]
    public void Patch_Application_Test() {
      test.createApplication();

      var response = test.client.PatchApplication(test.application.id, new Dictionary<string, object> {
        {
          "application", new Dictionary<string, object> {
            {
              "passwordlessConfiguration", new Dictionary<string, object> {
                {"enabled", false}
              }
            }, {
              "registrationConfiguration", new Dictionary<string, object> {
                {"enabled", true}
              }
            }
          }
        }
      });
      test.assertSuccess(response);

      response = test.client.RetrieveApplication(test.application.id);
      Assert.IsFalse(response.successResponse.application.passwordlessConfiguration.enabled);
      Assert.IsTrue(response.successResponse.application.registrationConfiguration.enabled);
    }

    [Test]
    public void Cancel_Action_Test() {
      test.createApplication()
        .createUserAction("CSharpClientUserAction", true)
        .createUser()
        .actionUser();

      var request = new ActionRequest() {
        action = new ActionData() {
          actionerUserId = test.user.id,
          comment = "Cancel Action"
        }
      };
      var cancelResponse = test.client.CancelAction(test.userActionLog.id, request);
      test.assertSuccess(cancelResponse);
    }

    [Test]
    public void Create_Tenant_Test() {
      var tenantResponse = test.client.RetrieveTenants();
      test.assertSuccess(tenantResponse);

      var tenant = tenantResponse.successResponse.tenants[0];
      tenant.id = null;
      tenant.name = "C# Tenant";
      tenant.eventConfiguration = new EventConfiguration()
        .with(ec => ec.events = new Dictionary<domain.@event.EventType, EventConfigurationData> {
          {
            EventType.UserDelete, new EventConfigurationData().with(ecd => ecd.enabled = true)
          }
        });

      var createTenantResponse = test.client.CreateTenant(null, new TenantRequest().with(tr => tr.tenant = tenant));
      test.assertSuccess(createTenantResponse);

      var retrieveTenantResponse = test.client.RetrieveTenant(createTenantResponse.successResponse.tenant.id);
      test.assertSuccess(retrieveTenantResponse);
      var userDeleteEvent =
        retrieveTenantResponse.successResponse.tenant.eventConfiguration.events[EventType.UserDelete];
      Assert.NotNull(userDeleteEvent);
      Assert.True(userDeleteEvent.enabled);

      var deleteTenantResponse = test.client.DeleteTenant(createTenantResponse.successResponse.tenant.id);
      test.assertSuccess(deleteTenantResponse);
    }

    [Test]
    public void Retrieve_Application_Test() {
      test.createApplication();

      var response = test.client.RetrieveApplication(test.application.id);
      Assert.AreEqual("CSharp Client Test", response.successResponse.application.name);
      test.assertSuccess(response);
    }

    [Test]
    public void Retrieve_RefreshTokens_Test() {
      test.createApplication()
        .createUser();

      var response = test.client.RetrieveRefreshTokens((Guid) test.user.id);
      test.assertSuccess(response);
      Assert.IsNull(response.successResponse.refreshTokens);
    }

    [Test]
    public void Update_Application_Test() {
      test.createApplication()
        .updateApplication(test.application.with(a => a.name = "CSharp Client Test (Updated)"));

      var application = new Application()
        .with(app => app.name = "CSharp Client Test (updated)");
      var response = test.client.UpdateApplication(TestBuilder.ApplicationId,
        new ApplicationRequest()
          .with(ar => ar.application = application));
      Assert.AreEqual("CSharp Client Test (updated)", response.successResponse.application.name);
      test.assertSuccess(response);
    }

    [Test]
    public void Validate_JWT_Test() {
      test.createApplication().createUser().login();

      var response = test.client.ValidateJWT(test.token);
      test.assertSuccess(response);

      Assert.AreEqual(response.successResponse.jwt.sub.ToString(), test.user.id.ToString());
      Assert.AreEqual(response.successResponse.jwt["applicationId"].ToString(), test.application.id.ToString());
    }

    [Test]
    public void Retrieve_Public_Keys_Test() {
      test.createApplication().createUser();

      // No Application Specific Public Keys
      var response = test.client.RetrieveJWTPublicKey(test.application.id.ToString());
      test.assertMissing(response);

      response = test.client.RetrieveJWTPublicKeys();
      test.assertSuccess(response);
    }

    [Test]
    public void Deactivate_Application_Test() {
      var response = test.createApplication()
        .client.DeactivateApplication(TestBuilder.ApplicationId);
      test.assertSuccess(response);
    }

    [Test]
    public void Reactivate_Application_Test() {
      Deactivate_Application_Test();

      var response = test.client.ReactivateApplication(TestBuilder.ApplicationId);
      test.assertSuccess(response);

      var retrieveResponse = test.client.RetrieveApplication(TestBuilder.ApplicationId);
      Assert.AreEqual("CSharp Client Test", retrieveResponse.successResponse.application.name);
      Assert.IsTrue(retrieveResponse.successResponse.application.active);
      test.assertSuccess(retrieveResponse);
    }

    [Test]
    public void Register_Test() {
      test.createApplication().createUser();

      //test retrieval
      var testRetrieve = test.client.RetrieveRegistration(test.user.id, TestBuilder.ApplicationId);
      Assert.AreEqual(test.user.username, testRetrieve.successResponse.registration.username);
      test.assertSuccess(testRetrieve);

      //test update
      var userRegistration = new UserRegistration()
        .with(ur => ur.applicationId = TestBuilder.ApplicationId)
        .with(ur => ur.username = test.user.username)
        .with(ur => ur.usernameStatus = ContentStatus.ACTIVE)
        .with(ur => ur.cleanSpeakId = new Guid("9af3fc1d-9236-4793-93df-aeac5f67f23e"));

      var updateResponse = test.client.UpdateRegistration(test.user.id,
        new RegistrationRequest()
          .with(rr => rr.registration = userRegistration));
      Assert.AreEqual(test.user.username, updateResponse.successResponse.registration.username);
      test.assertSuccess(updateResponse);

      // Delete Registration and User
      test.assertSuccess(test.client.DeleteRegistration(test.user.id, TestBuilder.ApplicationId));
      test.assertSuccess(test.client.DeleteUser(test.user.id));

      // test empty retrieval
      var randomUserId = new Guid("f64992f5-c705-47b2-bc88-4046ac8a82ee");
      test.assertMissing(test.client.RetrieveRegistration(randomUserId, TestBuilder.ApplicationId));
    }

    [Test]
    public void systemConfiguration() {
      var response = test.client.RetrieveSystemConfiguration();
      test.assertSuccess(response);
    }

    [Test]
    public void groups() {
      var retrieveResponse = test.client.RetrieveGroups();
      test.assertSuccess(retrieveResponse);

      if (retrieveResponse.successResponse.groups != null && retrieveResponse.successResponse.groups.Count > 0) {
        retrieveResponse.successResponse.groups.ForEach(g => {
          if (g.name.Equals("C# Group")) {
            test.client.DeleteGroup(g.id);
          }
        });
      }

      var createResponse = test.client.CreateGroup(null, new GroupRequest()
        .with(gr => gr.@group = new Group().with(g => g.name = "C# Group")));
      test.assertSuccess(createResponse);
      retrieveResponse = test.client.RetrieveGroups();
      test.assertSuccess(retrieveResponse);

      // Use a tenantId
      var tenantResponse = test.client.RetrieveTenants();
      test.assertSuccess(tenantResponse);

      var tenantId = tenantResponse.successResponse.tenants[0].id ?? throw new NullReferenceException();
      var tenantClient = test.newClientWithTenantId(tenantId);

      var tenantGroupRetrieveResponse = tenantClient.RetrieveGroup(createResponse.successResponse.group.id);
      test.assertSuccess(tenantGroupRetrieveResponse);

      // 400, bad tenant Id
      var badTenantClient = test.newClientWithTenantId(new Guid("40602225-d65c-4801-8696-9654e731b5da"));

      tenantGroupRetrieveResponse = badTenantClient.RetrieveGroup(createResponse.successResponse.group.id);
      test.assertStatusCode(tenantGroupRetrieveResponse, 400);

      // 404, Wrong tenant Id
      var createTenantResponse =
        test.client.CreateTenant(null, new TenantRequest()
          .with(tr => tr.tenant = new Tenant().with(t => t.name = "C# Tenant"))
          .with(tr => tr.sourceTenantId = tenantId));
      test.assertSuccess(createTenantResponse);

      var wrongTenantClient =
        test.newClientWithTenantId(createTenantResponse.successResponse.tenant.id ??
                                   throw new NullReferenceException());

      tenantGroupRetrieveResponse = wrongTenantClient.RetrieveGroup(createResponse.successResponse.group.id);
      test.assertMissing(tenantGroupRetrieveResponse);

      var deleteResponse = test.client.DeleteTenant(createTenantResponse.successResponse.tenant.id);
      test.assertSuccess(deleteResponse);
    }

    [Test]
    public void identityProviders() {
      var retrieveResponse = test.client.RetrieveIdentityProviders();
      test.assertSuccess(retrieveResponse);

      if (retrieveResponse.successResponse.identityProviders != null &&
          retrieveResponse.successResponse.identityProviders.Count > 0) {
        retrieveResponse.successResponse.identityProviders.ForEach(idp => {
          if (idp.GetType() == typeof(ExternalJWTIdentityProvider)) {
            var identityProvider = (ExternalJWTIdentityProvider) idp;
            if (identityProvider.name.Equals("C# IdentityProvider")) {
              test.client.DeleteIdentityProvider(identityProvider.id);
            }
          }
        });
      }

      var createResponse =
        test.client.CreateIdentityProvider(null,
          new IdentityProviderRequest()
            .with(ipr => ipr.identityProvider = new ExternalJWTIdentityProvider()
              .with(idp => idp.name = "C# IdentityProvider")
              .with(idp => idp.headerKeyParameter = "kid")
              .with(idp => idp.uniqueIdentityClaim = "username")));

      test.assertSuccess(createResponse);
      retrieveResponse = test.client.RetrieveIdentityProviders();
      test.assertSuccess(retrieveResponse);
    }

    [Test]
    public void integrations() {
      var response = test.client.RetrieveIntegration();
      test.assertSuccess(response);

      Assert.IsNotNull(response.successResponse.integrations.cleanspeak);
      Assert.IsNotNull(response.successResponse.integrations.kafka); 
    }

    [Test]
    public void Login_Test() {
      test.createApplication()
        .createUser()
        .callClient(client => test.assertSuccess(client.Login(new LoginRequest()
          .with(lr => lr.applicationId = TestBuilder.ApplicationId)
          .with(lr => lr.loginId = TestBuilder.emailAddress)
          .with(lr => lr.password = "password")
          .with(lr => lr.ipAddress = "10.0.1.129"))));
    }

    [Test]
    public void Tenant_Test() {
      var response = test.client.RetrieveTenants();
      test.assertSuccess(response);

      Assert.IsNotNull(response.successResponse.tenants);
      Assert.AreEqual(response.successResponse.tenants[0].name, "Default");

      // Make a copy of the default tenant
      var createResponse =
        test.client.CreateTenant(null, new TenantRequest()
          .with(tr => tr.tenant = new Tenant().with(t => t.name = "C# Tenant"))
          .with(tr => tr.sourceTenantId = response.successResponse.tenants[0].id));
      test.assertSuccess(createResponse);
      Assert.AreEqual(createResponse.successResponse.tenant.name, "C# Tenant");
      Assert.IsNotNull(createResponse.successResponse.tenant.id);

      var deleteResponse = test.client.DeleteTenant(createResponse.successResponse.tenant.id);
      test.assertSuccess(deleteResponse);
    }

    [Test]
    public void UnverifiedUserLogin_Test() {
      var tenantResponse = test.client.RetrieveTenants();

      test.assertSuccess(tenantResponse);

      // Retrieve the default verification template
      var emailTemplateResponse = test.client.RetrieveEmailTemplates();
      test.assertSuccess(emailTemplateResponse);
      var emailVerificationTemplate = emailTemplateResponse.successResponse.emailTemplates[0];
      Assert.IsNotNull(emailVerificationTemplate);

      // Create a second tenant, based on the default tenant, with email verification enabled
      var defaultTenant = tenantResponse.successResponse.tenants.Find(tenant => tenant.name.Equals("Default"));

      defaultTenant.emailConfiguration.verifyEmail = true;
      defaultTenant.emailConfiguration.verificationEmailTemplateId = emailVerificationTemplate.id;
      defaultTenant.name = "Verification Required Tenant";
      defaultTenant.id = null;

      tenantResponse =
        test.client.CreateTenant(null, new TenantRequest().with(request => request.tenant = defaultTenant));
      test.assertSuccess(tenantResponse);
      var verificationRequiredTenant = tenantResponse.successResponse.tenant;

      // Create a new application within the new tenant requiring email verification
      var applicationResponse = test.client.RetrieveApplications();

      test.assertSuccess(applicationResponse);

      var verificationRequiredApplication = applicationResponse.successResponse.applications.Find(application =>
        application.name.Equals("Verification Required Application"));

      var tenantClient = test.newClientWithTenantId((Guid) verificationRequiredTenant.id);

      if (verificationRequiredApplication == null) {
        applicationResponse = tenantClient.CreateApplication(null,
          new ApplicationRequest().with(request => request.application = new Application()
            .with(application => application.name = "Verification Required Application")
            .with(application => application.tenantId = verificationRequiredTenant.id)));

        test.assertSuccess(applicationResponse);

        verificationRequiredApplication = applicationResponse.successResponse.application;
      }

      var registrationRequest =
        tenantClient.Register(null, new RegistrationRequest()
          .with(request => request.user = new User()
            .with(user => user.email = Guid.NewGuid() + "@example.com")
            .with(user => user.password = "password"))
          .with(request => request.registration = new UserRegistration()
            .with(registration => registration.applicationId = verificationRequiredApplication.id)));

      test.assertSuccess(registrationRequest);

      var loginResponse = tenantClient.Login(new LoginRequest()
        .with(request => request.applicationId = verificationRequiredApplication.id)
        .with(request => request.loginId = registrationRequest.successResponse.user.email)
        .with(request => request.password = "password"));

      Assert.AreEqual(loginResponse.statusCode, 212);
      Assert.NotNull(loginResponse.successResponse);

      // Cleanup the verificationRequiredTenant, this will also delete the verificationRequiredApplication
      var deleteTenantResponse = test.client.DeleteTenant(verificationRequiredTenant.id);
      test.assertSuccess(deleteTenantResponse);
    }
  }

  /// <summary>
  /// A collection of unit tests that are separate from any network calls. Simply testing that the code behaves as expected.
  /// </summary>
  [TestFixture]
  public class FusionAuthClientUnitTest {

    /// <summary>
    /// Copied from the DefaultRestClient. You will need to update both if you have issues with converters.
    /// </summary>
    static FusionAuthClientUnitTest() {
      JsonConvert.DefaultSettings = () =>
        new JsonSerializerSettings {
          NullValueHandling = NullValueHandling.Ignore,
          Converters = new List<JsonConverter> {
            new StringEnumConverter(),
            new DateTimeOffsetConverter(),
            new IdentityProviderConverter()
          },
          ContractResolver = new DefaultContractResolver()
        };
    }
    
    [Test]
    public void JWTOtherFieldsTest() {
      var json = ReadManifestData<FusionAuthClientUnitTest>("JWTOtherFieldsTest.json");

      var jwt = JsonConvert.DeserializeObject<JWT>(json);

      Assert.AreEqual(jwt["0"], new JArray() {"role 1"});
      Assert.AreEqual(jwt["1"], "Test");
      Assert.AreEqual(jwt["2"], 2);
      Assert.AreEqual(jwt["3"], new JArray() {
        "a",
        "list",
        "of",
        "roles"
      });
    }

    public static string ReadManifestData<TSource>(string embeddedFileName) where TSource : class {
      var assembly = typeof(TSource).GetTypeInfo().Assembly;
      var resourceName = assembly.GetManifestResourceNames()
        .First(s => s.EndsWith(embeddedFileName, StringComparison.CurrentCultureIgnoreCase));

      using (var stream = assembly.GetManifestResourceStream(resourceName)) {
        if (stream == null) {
          throw new InvalidOperationException("Could not load manifest resource stream.");
        }

        using (var reader = new StreamReader(stream)) {
          return reader.ReadToEnd();
        }
      }
    }
  }
}