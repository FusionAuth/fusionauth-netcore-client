using System;
using io.fusionauth.converters.helpers;
using io.fusionauth.domain.provider;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace io.fusionauth.converters {
  public class IdentityProviderConverter : JsonConverter {
    public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) {
      if (value == null) {
        return;
      }

      writer.WriteValue(value);
    }

    public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) {
      var json = JObject.Load(reader);
      if (json["type"].Value<string>() == "Apple") {
        return json.ToObject<AppleIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "EpicGames") {
        return json.ToObject<EpicGamesIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "ExternalJWT") {
        return json.ToObject<ExternalJWTIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "Facebook") {
        return json.ToObject<FacebookIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "Google") {
        return json.ToObject<GoogleIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "HYPR") {
        return json.ToObject<HYPRIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "LinkedIn") {
        return json.ToObject<LinkedInIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "Nintendo") {
        return json.ToObject<NintendoIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "OpenIDConnect") {
        return json.ToObject<OpenIdConnectIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "SAMLv2") {
        return json.ToObject<SAMLv2IdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "SonyPSN") {
        return json.ToObject<SonyPSNIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "Steam") {
        return json.ToObject<SteamIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "Twitch") {
        return json.ToObject<TwitchIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "Twitter") {
        return json.ToObject<TwitterIdentityProvider>(serializer);
      }

      if (json["type"].Value<string>() == "Xbox") {
        return json.ToObject<XboxIdentityProvider>(serializer);
      }

      return null;
    }

    public override bool CanConvert(Type objectType) => objectType == typeof(IdentityProvider);
  }
}
