using System;
using io.fusionauth.domain;

namespace io.fusionauth {
  public class Example {
    private const string apiKey = "6b87a398-39f2-4692-927b-13188a81a9a3";

    private const string fusionAuthURL = "http://localhost:9011";

    private readonly FusionAuthSyncClient client;

    public Example(string apiKey, string fusionAuthURL) {
      client = new FusionAuthSyncClient(apiKey, fusionAuthURL);
    }

    public User GetUserByEmail(string email) {
      var response = client.RetrieveUserByEmail("user@example.com");
      if (response.WasSuccessful()) {
        var user = response.successResponse.user;
        return user;
      }

      if (response.errorResponse != null) {
        // Error Handling
        var errors = response.errorResponse;
        return null;
      }
      
      if (response.exception != null) {
        // Exception Handling
        var exception = response.exception;
        return null;
      }

      return null;
    }
  }
}
