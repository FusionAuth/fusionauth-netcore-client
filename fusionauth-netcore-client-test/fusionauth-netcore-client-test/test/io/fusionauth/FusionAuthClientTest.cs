using System;
using System.Collections.Generic;
using System.Diagnostics;
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
using io.fusionauth.domain.search;
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

    public readonly Guid ApplicationId = Guid.NewGuid();

    public string emailAddress => "csharpclient-" + ApplicationId + "@fusionauth.io";

    private readonly Stack<Func<ClientResponse<RESTVoid>>> cleanupActions = new Stack<Func<ClientResponse<RESTVoid>>>();

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

    public void addCleanup(Func<ClientResponse<RESTVoid>> cleanup) {
      cleanupActions.Push(cleanup);
    }

    public void cleanup() {
      // Delete dependents first and attempt every cleanup even when a deletion fails.
      var failures = new List<string>();
      while (cleanupActions.Count > 0) {
        var response = cleanupActions.Pop()();
        // Some tests explicitly delete resources while exercising the API.
        if (response.exception != null || response.errorResponse != null ||
            (response.statusCode != 200 && response.statusCode != 404)) {
          failures.Add("Status [" + response.statusCode + "]: " +
            (response.errorResponse != null ? JsonConvert.SerializeObject(response.errorResponse) : response.exception?.ToString()));
        }
      }

      Assert.IsEmpty(failures, "Resource cleanup failed");
    }

    public TestBuilder createUser() {
      var newUser = new User()
        .with(u => u.email = emailAddress)
        .with(u => u.username = "csharpclient-" + ApplicationId)
        .with(u => u.password = "password");

      var newRegistration = new UserRegistration()
        .with(r => r.applicationId = ApplicationId)
        .with(r => r.username = newUser.username);

      var response = client.Register(null, new RegistrationRequest().with(rr => rr.user = newUser)
        .with(rr => rr.registration = newRegistration)
        .with(rr => rr.sendSetPasswordEmail = false)
        .with(rr => rr.skipVerification = true));
      assertSuccess(response);
      user = response.successResponse.user;
      var userId = user.id;
      addCleanup(() => client.DeleteUser(userId));
      waitForLogin(client, user);
      Assert.AreEqual(newUser.username, user.username);
      return this;
    }

    public TestBuilder createUserAction(string actionName, bool isTemporal) {
      var request = new UserActionRequest() {
        userAction = new UserAction() {
          name = actionName + "-" + ApplicationId,
          temporal = isTemporal
        }
      };
      var response = client.CreateUserAction(null, request);
      assertSuccess(response);
      this.userAction = response.successResponse.userAction;
      var userActionId = this.userAction.id;
      addCleanup(() => client.DeleteUserAction(userActionId));
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

    public TestBuilder login(string ipAddress = null) {
      var response = client.Login(new LoginRequest()
        .with(lr => lr.applicationId = application.id)
        .with(lr => lr.loginId = user.email)
        .with(lr => lr.password = "password")
        .with(lr => lr.ipAddress = ipAddress));
      assertSuccess(response);

      token = response.successResponse.token;
      user = response.successResponse.user;
      waitForLogin(client, user);
      return this;
    }

    public void waitForLogin(FusionAuthSyncClient client, User user) {
      Assert.IsNotNull(user.lastLoginInstant);
      var statusResponse = client.RetrieveSystemStatusUsingAPIKey();
      assertSuccess(statusResponse);
      var healthChecks = statusResponse.successResponse["healthChecks"] as JObject;
      Assert.IsNotNull(healthChecks);
      var usesElasticsearch = healthChecks["ElasticsearchCluster"] != null;
      var searchRequest = new SearchRequest()
        .with(sr => sr.search = new UserSearchCriteria()
          .with(sc => sc.queryString = "id:\"" + user.id + "\" AND lastLoginInstant:" + user.lastLoginInstant.Value.ToUnixTimeMilliseconds()));

      // LoginQueue writes metrics and the database timestamp before reindexing. Filter on the indexed timestamp,
      // because search responses reload users from the database and can otherwise hide a stale search document.
      var timer = Stopwatch.StartNew();
      while (timer.Elapsed < TimeSpan.FromSeconds(10)) {
        var response = client.RetrieveUser(user.id);
        assertSuccess(response);
        if (response.successResponse.user.lastLoginInstant == user.lastLoginInstant) {
          if (!usesElasticsearch) {
            return;
          }

          var searchResponse = client.SearchUsersByQuery(searchRequest);
          assertSuccess(searchResponse);
          if (searchResponse.successResponse.users.Any(u => u.id == user.id)) {
            return;
          }
        }

        System.Threading.Thread.Sleep(50);
      }

      Assert.Fail("Timed out waiting for login metrics and search indexing for user [" + user.id + "]");
    }

    public TestBuilder updateApplication(Application application) {
      var response = client.UpdateApplication(ApplicationId, new ApplicationRequest()
        .with(ar => ar.application = application));
      assertSuccess(response);

      this.application = response.successResponse.application;
      return this;
    }

    public TestBuilder createApplication() {
      var application = new Application()
        .with(app => app.name = "CSharp Client Test-" + ApplicationId);

      var response = client.CreateApplication(ApplicationId,
        new ApplicationRequest().with(ar => ar.application = application));
      assertSuccess(response);
      this.application = response.successResponse.application;
      addCleanup(() => client.DeleteApplication(ApplicationId));
      Assert.AreEqual(application.name, this.application.name);
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

    [TearDown]
    public void cleanup() {
      test.cleanup();
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
      var tenantId = createTenantResponse.successResponse.tenant.id;
      test.addCleanup(() => test.client.DeleteTenant(tenantId));

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
      Assert.AreEqual("CSharp Client Test-" + test.ApplicationId, response.successResponse.application.name);
      test.assertSuccess(response);
    }

    [Test]
    public void Retrieve_RefreshTokens_Test() {
      test.createApplication()
        .createUser();

      var response = test.client.RetrieveRefreshTokens((Guid) test.user.id);
      test.assertSuccess(response);
      // FusionAuth may return null or an empty list when no refresh tokens exist
      Assert.IsTrue(response.successResponse.refreshTokens == null || response.successResponse.refreshTokens.Count == 0);
    }

    [Test]
    public void Update_Application_Test() {
      test.createApplication();

      // Null out multiFactorConfiguration to avoid sending deprecated enum values (e.g. ChallengeOnHighRisk)
      // that the current FusionAuth version no longer accepts
      test.application.multiFactorConfiguration = null;
      test.updateApplication(test.application.with(a => a.name = "CSharp Client Test (Updated)-" + test.ApplicationId));

      var application = new Application()
        .with(app => app.name = "CSharp Client Test (updated)-" + test.ApplicationId);
      var response = test.client.UpdateApplication(test.ApplicationId,
        new ApplicationRequest()
          .with(ar => ar.application = application));
      Assert.AreEqual(application.name, response.successResponse.application.name);
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
        .client.DeactivateApplication(test.ApplicationId);
      test.assertSuccess(response);
    }

    [Test]
    public void Reactivate_Application_Test() {
      Deactivate_Application_Test();

      var response = test.client.ReactivateApplication(test.ApplicationId);
      test.assertSuccess(response);

      var retrieveResponse = test.client.RetrieveApplication(test.ApplicationId);
      Assert.AreEqual("CSharp Client Test-" + test.ApplicationId, retrieveResponse.successResponse.application.name);
      Assert.IsTrue(retrieveResponse.successResponse.application.active);
      test.assertSuccess(retrieveResponse);
    }

    [Test]
    public void Register_Test() {
      test.createApplication().createUser();

      //test retrieval
      var testRetrieve = test.client.RetrieveRegistration(test.user.id, test.ApplicationId);
      Assert.AreEqual(test.user.username, testRetrieve.successResponse.registration.username);
      test.assertSuccess(testRetrieve);

      //test update
      var userRegistration = new UserRegistration()
        .with(ur => ur.applicationId = test.ApplicationId)
        .with(ur => ur.username = test.user.username)
        .with(ur => ur.usernameStatus = ContentStatus.ACTIVE)
        .with(ur => ur.cleanSpeakId = new Guid("9af3fc1d-9236-4793-93df-aeac5f67f23e"));

      var updateResponse = test.client.UpdateRegistration(test.user.id,
        new RegistrationRequest()
          .with(rr => rr.registration = userRegistration));
      Assert.AreEqual(test.user.username, updateResponse.successResponse.registration.username);
      test.assertSuccess(updateResponse);

      // Delete Registration and User
      test.assertSuccess(test.client.DeleteRegistration(test.user.id, test.ApplicationId));
      test.assertSuccess(test.client.DeleteUser(test.user.id));

      // test empty retrieval
      var randomUserId = new Guid("f64992f5-c705-47b2-bc88-4046ac8a82ee");
      test.assertMissing(test.client.RetrieveRegistration(randomUserId, test.ApplicationId));
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

      var createResponse = test.client.CreateGroup(null, new GroupRequest()
        .with(gr => gr.@group = new Group().with(g => g.name = "C# Group-" + test.ApplicationId)));
      test.assertSuccess(createResponse);
      var groupId = createResponse.successResponse.group.id;
      test.addCleanup(() => test.client.DeleteGroup(groupId));
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
      var wrongTenantId = createTenantResponse.successResponse.tenant.id;
      test.addCleanup(() => test.client.DeleteTenant(wrongTenantId));

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

      var keyResponse =
        test.client.GenerateKey(null,
          new KeyRequest()
            .with(kr => kr.key = new Key()
              .with(k => k.algorithm = KeyAlgorithm.HS256)
              .with(k => k.name = "C# IdentityProvider Verification Key-" + test.ApplicationId)));
      test.assertSuccess(keyResponse);
      var keyId = keyResponse.successResponse.key.id ?? throw new InvalidOperationException("Expected a key id to be returned from GenerateKey.");
      test.addCleanup(() => test.client.DeleteKey(keyId));

      var createResponse =
        test.client.CreateIdentityProvider(null,
          new IdentityProviderRequest()
            .with(ipr => ipr.identityProvider = new ExternalJWTIdentityProvider()
              .with(idp => idp.type = IdentityProviderType.ExternalJWT)
              .with(idp => idp.name = "C# IdentityProvider-" + test.ApplicationId)
              .with(idp => idp.headerKeyParameter = "kid")
              .with(idp => idp.uniqueIdentityClaim = "username")
              .with(idp => idp.verificationKeyIds = new List<Guid> {keyId})));

      test.assertSuccess(createResponse);
      var identityProviderId = ((ExternalJWTIdentityProvider) createResponse.successResponse.identityProvider).id;
      test.addCleanup(() => test.client.DeleteIdentityProvider(identityProviderId));
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
        .login("10.0.1.129");
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
      var tenantId = createResponse.successResponse.tenant.id;
      test.addCleanup(() => test.client.DeleteTenant(tenantId));
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

      // Skip if no email templates exist (kickstart may not seed any)
      if (emailTemplateResponse.successResponse.emailTemplates == null ||
          emailTemplateResponse.successResponse.emailTemplates.Count == 0) {
        Assert.Ignore("No email templates available — skipping UnverifiedUserLogin_Test");
        return;
      }

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
      var verificationRequiredTenantId = verificationRequiredTenant.id;
      test.addCleanup(() => test.client.DeleteTenant(verificationRequiredTenantId));

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
      test.waitForLogin(tenantClient, loginResponse.successResponse.user);

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
    public void Cleanup_Resources_Reports_Failure_Test() {
      var builder = new TestBuilder();
      var deleted = new List<int>();
      builder.addCleanup(() => {
        deleted.Add(1);
        return new ClientResponse<RESTVoid> {statusCode = 200};
      });
      builder.addCleanup(() => {
        deleted.Add(2);
        return new ClientResponse<RESTVoid> {statusCode = 500};
      });

      Assert.Throws<AssertionException>(() => builder.cleanup());

      CollectionAssert.AreEqual(new[] {2, 1}, deleted);
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

    [Test]
    public void InstantCorrectlyDeserialized() {
      var json = ReadManifestData<FusionAuthClientUnitTest>("ConsentTest.json");

      var consent = JsonConvert.DeserializeObject<Consent>(json);

      var expectedDateString = "2020-07-21 19:52:22.909";
      DateTime dateTime = DateTime.Parse(expectedDateString,
                          System.Globalization.CultureInfo.InvariantCulture);
      DateTimeOffset dateTimeOffset = new DateTimeOffset(dateTime, TimeSpan.Zero);
      Assert.AreEqual(dateTimeOffset, consent.insertInstant);
    }

    [Test]
    public void ExpCorrectlyDeserialized() {
      var json = ReadManifestData<FusionAuthClientUnitTest>("JWTDateTimeTest.json");

      var expectedDateString = "2020-07-21 19:52:22";
      DateTime dateTime = DateTime.Parse(expectedDateString,
                          System.Globalization.CultureInfo.InvariantCulture);
      DateTimeOffset dateTimeOffset = new DateTimeOffset(dateTime, TimeSpan.Zero);
      JWT jwt = JsonConvert.DeserializeObject<JWT>(json);
      Assert.AreEqual(dateTimeOffset, jwt.exp);
    }

    [Test]
    public void IatCorrectlyDeserialized() {
      var json = ReadManifestData<FusionAuthClientUnitTest>("JWTDateTimeTest.json");

      var expectedDateString = "2020-07-21 19:52:21";
      DateTime dateTime = DateTime.Parse(expectedDateString,
                          System.Globalization.CultureInfo.InvariantCulture);
      DateTimeOffset dateTimeOffset = new DateTimeOffset(dateTime, TimeSpan.Zero);
      JWT jwt = JsonConvert.DeserializeObject<JWT>(json);
      Assert.AreEqual(dateTimeOffset, jwt.iat);
    }

    [Test]
    public void NbfCorrectlyDeserialized() {
      var json = ReadManifestData<FusionAuthClientUnitTest>("JWTDateTimeTest.json");

      var expectedDateString = "2020-07-21 19:52:21";
      DateTime dateTime = DateTime.Parse(expectedDateString,
                          System.Globalization.CultureInfo.InvariantCulture);
      DateTimeOffset dateTimeOffset = new DateTimeOffset(dateTime, TimeSpan.Zero);
      JWT jwt = JsonConvert.DeserializeObject<JWT>(json);
      Assert.AreEqual(dateTimeOffset, jwt.nbf);
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
