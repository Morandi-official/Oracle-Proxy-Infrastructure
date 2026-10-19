using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace OracleProxy.WgAlpha;

// R114 standalone GUI functionality. Never calls SCM, a network API, WFP,
// tunnels or GitHub. Files contain key material; logs/reports contain NONE.
internal static class LocalWireGuardKeys
{
    private const string PrivateFile = "OracleProxyAlphaTest.privatekey";
    private const string PublicFile = "OracleProxyAlphaTest.publickey";
    private const string FolderPrefix = "OracleProxyAlphaKeys-";

    internal sealed record Created(string DirectoryPath, string PublicKey);

    internal static bool SelfTest()
    {
        // RFC 7748 section 6.1: Alice's Curve25519 scalar and public key.
        byte[] input = Convert.FromHexString(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] known = Convert.FromHexString(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        try
        {
            byte[] answer = new X25519PrivateKeyParameters(input,0)
                .GeneratePublicKey().GetEncoded();
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(answer,known))
                    return false;
            }
            finally { CryptographicOperations.ZeroMemory(answer); }

            // No output or secret file. Fresh OS-random seed + canonical WG clamp.
            byte[] sample = new byte[32];
            byte[] pub = new byte[32];
            try
            {
                RandomNumberGenerator.Fill(sample);
                Clamp(sample);
                pub = new X25519PrivateKeyParameters(sample,0)
                    .GeneratePublicKey().GetEncoded();
                return pub.Length==32 &&
                    (sample[0]&7)==0 && (sample[31]&0x80)==0 &&
                    (sample[31]&0x40)!=0 &&
                    Convert.FromBase64String(Convert.ToBase64String(pub)).Length==32;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sample);
                CryptographicOperations.ZeroMemory(pub);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(known);
        }
    }

    private static void Clamp(byte[] key)
    {
        if(key.Length!=32)throw new CryptographicException("BAD_SCALAR_LENGTH");
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
    }

    private static bool SafeParent(string path)
    {
        if(!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(path))
            return false;
        try
        {
            var full=Path.GetFullPath(path);
            if(!Directory.Exists(full))return false;
            var current=new DirectoryInfo(full);
            // Reject junctions, symlinks and network/reparse aliases.
            while(current!=null)
            {
                if(current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    return false;
                current=current.Parent;
            }
            var parent=new DirectoryInfo(full);
            return parent.Parent!=null && !full.StartsWith(@"\\",StringComparison.Ordinal);
        }
        catch { return false; }
    }

    private static FileSystemAccessRule AllowedRule(SecurityIdentifier sid,bool directory) =>
        new(sid,FileSystemRights.FullControl,
            directory?InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit:InheritanceFlags.None,
            PropagationFlags.None,AccessControlType.Allow);

    private static DirectorySecurity DirectoryAcl(SecurityIdentifier current)
    {
        var acl=new DirectorySecurity();
        acl.SetOwner(current);
        acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(AllowedRule(current,true));
        acl.AddAccessRule(AllowedRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),true));
        return acl;
    }

    private static FileSecurity FileAcl(SecurityIdentifier current)
    {
        var acl=new FileSecurity();
        acl.SetOwner(current);
        acl.SetAccessRuleProtection(true,false);
        acl.AddAccessRule(AllowedRule(current,false));
        acl.AddAccessRule(AllowedRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),false));
        return acl;
    }

    private static bool IsOnlyExpectedPrincipals(string path,bool directory,
        SecurityIdentifier principal)
    {
        try
        {
            FileSystemSecurity acl=directory
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access|AccessControlSections.Owner)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Access|AccessControlSections.Owner);
            if(!acl.AreAccessRulesProtected ||
                acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
                owner.Value!=principal.Value)return false;
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            {
                if(rule.AccessControlType!=AccessControlType.Allow)continue;
                if(rule.IdentityReference.Value!=principal.Value &&
                   rule.IdentityReference.Value!="S-1-5-18")
                    return false;
            }
            return true;
        }
        catch{return false;}
    }

    private static void SaveKeyFile(string path,string base64,SecurityIdentifier owner)
    {
        // The parent folder is already verified and protected before the
        // first private byte is written. CreateNew refuses replacement.
        byte[] bytes=Encoding.ASCII.GetBytes(base64+"\n");
        try
        {
            using(var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,
                FileShare.None,4096,FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(true);
            }
            new FileInfo(path).SetAccessControl(FileAcl(owner));
            if(!IsOnlyExpectedPrincipals(path,false,owner))
                throw new IOException("KEY_FILE_ACL_NOT_VERIFIED");
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static Created Create(string selectedParent)
    {
        if(!SafeParent(selectedParent))
            throw new IOException("INVALID_OR_LINKED_OUTPUT_FOLDER");
        using var user=WindowsIdentity.GetCurrent();
        if(user.User is not SecurityIdentifier current)
            throw new IOException("LOCAL_USER_SID_UNAVAILABLE");

        // Never store the private key in app state, clipboard, report or logs.
        // A fresh, unique directory prevents accidental overwrite/reuse.
        string root=Path.Combine(Path.GetFullPath(selectedParent),
            FolderPrefix+Guid.NewGuid().ToString("N"));
        bool folderCreated=false;
        byte[] scalar=new byte[32];
        byte[] publicBytes=Array.Empty<byte>();
        try
        {
            // Fail closed on any race that creates the root before us.
            if(Directory.Exists(root) || File.Exists(root))
                throw new IOException("OUTPUT_ALREADY_EXISTS");
            Directory.CreateDirectory(root);
            folderCreated=true;
            new DirectoryInfo(root).SetAccessControl(DirectoryAcl(current));
            if(!IsOnlyExpectedPrincipals(root,true,current))
                throw new IOException("KEY_DIRECTORY_ACL_NOT_VERIFIED");

            RandomNumberGenerator.Fill(scalar);
            Clamp(scalar);
            publicBytes=new X25519PrivateKeyParameters(scalar,0)
                .GeneratePublicKey().GetEncoded();
            if(publicBytes.Length!=32)
                throw new CryptographicException("X25519_PUBLIC_KEY_BAD_LENGTH");
            string encodedPrivate=Convert.ToBase64String(scalar);
            string encodedPublic=Convert.ToBase64String(publicBytes);

            SaveKeyFile(Path.Combine(root,PrivateFile),encodedPrivate,current);
            SaveKeyFile(Path.Combine(root,PublicFile),encodedPublic,current);
            return new Created(root,encodedPublic);
        }
        catch
        {
            // Only remove exactly-owned files in our one new directory.
            // Never reset ACLs or delete unrelated data on failure.
            if(folderCreated && IsOnlyExpectedPrincipals(root,true,current))
            {
                foreach(string name in new[]{PrivateFile,PublicFile})
                {
                    string candidate=Path.Combine(root,name);
                    if(File.Exists(candidate) && IsOnlyExpectedPrincipals(candidate,false,current))
                    {
                        try { File.Delete(candidate); } catch { /* manual local cleanup */ }
                    }
                }
                try { Directory.Delete(root,false); } catch { /* manual local cleanup */ }
            }
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scalar);
            CryptographicOperations.ZeroMemory(publicBytes);
        }
    }

    // Invoked only inside a separate non-distributed GitHub CI build.
    internal static bool CiReadBackAndValidate(Created value)
    {
        try
        {
            using var identity=WindowsIdentity.GetCurrent();
            var owner=identity.User;
            if(owner==null ||
               !IsOnlyExpectedPrincipals(value.DirectoryPath,true,owner))return false;
            var privatePath=Path.Combine(value.DirectoryPath,PrivateFile);
            var publicPath=Path.Combine(value.DirectoryPath,PublicFile);
            if(!IsOnlyExpectedPrincipals(privatePath,false,owner) ||
               !IsOnlyExpectedPrincipals(publicPath,false,owner))return false;
            byte[] scalar=Convert.FromBase64String(File.ReadAllText(privatePath).Trim());
            byte[] publicBytes=Convert.FromBase64String(File.ReadAllText(publicPath).Trim());
            byte[] derived=new X25519PrivateKeyParameters(scalar,0)
                .GeneratePublicKey().GetEncoded();
            try
            {
                return scalar.Length==32 && publicBytes.Length==32 &&
                    value.PublicKey==Convert.ToBase64String(publicBytes) &&
                    CryptographicOperations.FixedTimeEquals(derived,publicBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(scalar);
                CryptographicOperations.ZeroMemory(publicBytes);
                CryptographicOperations.ZeroMemory(derived);
            }
        }
        catch{return false;}
    }
}
