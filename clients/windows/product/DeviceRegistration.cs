using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal static class DeviceRegistration
{
    internal static bool Confirmed(JsonObject? state)=>state?["registration"]?["status"]?.GetValue<string>()=="registered" && state?["device"]?["registered"]?.GetValue<bool>()==true && state?["tunnel"] is JsonObject;
    internal static string Version=>typeof(DeviceRegistration).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion ?? "0.3.0-rc18";
    internal static string ReportMode(string mode,bool registered,bool recovery)=>!registered?"pending":recovery?"recovery":mode is "disconnected" or "protected" or "connected"?mode:"unknown";
}
