using System;
using Newtonsoft.Json;

namespace io.fusionauth.converters
{
  public class DateTimeOffsetConverter : JsonConverter
  {
    public override bool CanRead => true;

    public override bool CanWrite => true;

    public override bool CanConvert(Type objectType)
    {
      return objectType == typeof(DateTimeOffset) || objectType == typeof(DateTimeOffset?);
    }

    public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
    {
      if (reader.TokenType == JsonToken.Null)
      {
        return null;
      }

      var value = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds((long)reader.Value);
      return new DateTimeOffset(value);
    }

    public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
    {
      if (value == null)
      {
        return;
      }

      var millis = ((DateTimeOffset)value - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
      writer.WriteValue(millis);
    }
  }
}

