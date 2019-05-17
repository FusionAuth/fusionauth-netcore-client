using System;
using Newtonsoft.Json;

namespace io.fusionauth.converters {
  public class DateTimeOffsetConverter : JsonConverter
  {
    public static readonly long GAP = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero).Ticks;

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

      var value = (long) reader.Value * TimeSpan.TicksPerMillisecond;
      return new DateTimeOffset(value + GAP, TimeSpan.Zero);
    }

    public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
    {
      if (value == null)
      {
        return;
      }

      var dto = (DateTimeOffset) value;
      var ticks = dto.UtcTicks - GAP;
      var millis = ticks / TimeSpan.TicksPerMillisecond;
      writer.WriteValue(millis);
    }
  }
}
