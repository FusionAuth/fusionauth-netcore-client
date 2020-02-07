using System;
using com.inversoft.error;

namespace io.fusionauth {
  public class ClientResponse<T> {
    public int statusCode;

    public T successResponse;

    public Errors errorResponse;

    public Exception exception;

    public bool WasSuccessful() {
      return status >= 200 && status <= 299 && exception == null;
    }
  }
}
