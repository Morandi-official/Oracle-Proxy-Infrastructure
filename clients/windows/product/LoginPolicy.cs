namespace OracleProxy.Product;

// Remember a revocable server session, never a password. DurableState is
// SYSTEM-DPAPI encrypted and writable only by SYSTEM / administrators.
internal static class LoginPolicy
{
    internal const long MaximumAge=30L*24*60*60;
    internal static bool Authorized(DurableState state,bool interactive,long now)
    {
        if(state.Token.Length==0 || state.LoginIssuedAt<=0 || now<state.LoginIssuedAt ||
           now>=state.SessionExpiresAt || now-state.LoginIssuedAt>=MaximumAge)return false;
        return interactive || state.RememberLoginUntil>now && state.RememberLoginUntil<=state.LoginIssuedAt+MaximumAge;
    }
    internal static void Start(DurableState state,long expires,bool remember,string username,long now)
    {
        if(expires<=now)throw new IOException("LOGIN_SESSION_EXPIRED");
        state.LoginIssuedAt=now;state.SessionExpiresAt=Math.Min(expires,now+MaximumAge);
        state.RememberLoginUntil=remember?now+MaximumAge:0;
        state.RememberedUsername=remember?username:"";
    }
    internal static void Enrolled(DurableState state,long now)=>
        state.SessionExpiresAt=Math.Min(now+MaximumAge,state.LoginIssuedAt+MaximumAge);
    internal static void Forget(DurableState state)
    {
        state.Token="";state.LoginIssuedAt=state.SessionExpiresAt=state.RememberLoginUntil=0;state.RememberedUsername="";
    }
}
