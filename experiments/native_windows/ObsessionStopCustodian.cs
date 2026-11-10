// SOURCE-ONLY EXPERIMENT. Staging compile and isolated semantic test only;
// no production SCM registration, host authority, or runtime installation.
// .NET Framework 4.x, Windows Service, no third-party dependencies.
// Protected host output is LOCAL_SYNTHETIC_HANDOFF_ONLY, never a recipient send.
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Web.Script.Serialization;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Vera.ObsessionStop
{
    public sealed class StopCustodian : ServiceBase
    {
#if STAGING_SELFTEST
        // Test-only binary lives in an isolated, disposable staging directory.
        // It must never be installed as the SCM service.
        private static readonly string Root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
#else
        private const string Root = @"C:\Program Files\VERA\ObsessionStopCustodian";
#endif
#if STAGING_SELFTEST
        // Selftests never claim or probe the real production pipe names.
        private static readonly string OperatorPipe = "VeraObsessionStopOperatorStageV1_" + Process.GetCurrentProcess().Id;
        private static readonly string PublishPipe = "VeraObsessionStopPublishStageV1_" + Process.GetCurrentProcess().Id;
#else
        private const string OperatorPipe = "VeraObsessionStopOperatorV1";
        private const string PublishPipe = "VeraObsessionStopPublishV1";
#endif
        private static readonly Regex Generation = new Regex(@"\A[a-zA-Z0-9_-]{8,96}\z", RegexOptions.Compiled);
        private static readonly Regex ArtifactId = new Regex(@"\A[a-f0-9]{64}\z", RegexOptions.Compiled);
        private static readonly Regex Digest = new Regex(@"\A[a-f0-9]{64}\z", RegexOptions.Compiled);
        // Resident proposal IDs/digests are typed; the protected artifact
        // hash and artifact filename remain raw 64-character lowercase hex.
        private static readonly Regex TypedDigest = new Regex(@"\Asha256:[a-f0-9]{64}\z", RegexOptions.Compiled);
        private static readonly string[] HandoffKeys = {
            "schema", "scope", "proposal_digest", "proposal",
            "delivery_verified", "contact_authorized"
        };
        private static readonly string[] ProposalKeys = {
            "schema", "proposal_id", "idempotency_key", "event_id", "generation",
            "goal_digest", "created_at", "expires_at", "target_class", "message",
            "reason", "salience", "execution_authorized", "contact_authorized",
            "delivery_verified", "provider_evidence", "provenance", "origin",
            "category", "propose_only", "ttl_seconds", "evidence_class"
        };
        private readonly object gate = new object();
        private readonly HashSet<string> revoked = new HashSet<string>(StringComparer.Ordinal);
        private readonly Dictionary<string, Grant> grants = new Dictionary<string, Grant>(StringComparer.Ordinal);
        private volatile bool running;
        private bool healthy;
        private SecurityIdentifier residentSid;
        private Thread operatorThread;
        private Thread publishThread;

        // The stock NamedPipeServerStream name-taking constructor does not
        // request FILE_FLAG_FIRST_PIPE_INSTANCE. Reserve both names *before*
        // SCM acknowledges start; never release/recreate them between clients.
        private const uint PipeAccessDuplex = 0x00000003;
        private const uint FileFlagOverlapped = 0x40000000;
        private const uint FileFlagFirstInstance = 0x00080000;
        private const uint PipeRejectRemoteClients = 0x00000008;

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafePipeHandle CreateNamedPipe(
            string fullName, uint openMode, uint pipeMode, uint maxInstances,
            uint outBufferSize, uint inBufferSize, uint timeout,
            ref SecurityAttributes attributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CancelIoEx(SafePipeHandle file, IntPtr overlapped);

        // A deadline whose outstanding asynchronous callback cannot be
        // settled means this retained first-instance pipe must not be reused.
        private sealed class FatalPipeIoException : IOException
        {
            public FatalPipeIoException(string reason) : base(reason) { }
        }

        private struct Grant
        {
            public string Generation;
            public string Artifact;
            public string Digest;
            public long ExpiresUtcTicks;
        }

        public StopCustodian()
        {
            ServiceName = "VeraObsessionStopCustodian";
            CanStop = true;
            AutoLog = false;
        }

        private static string PathInside(string filename)
        {
            return Path.Combine(Root, filename);
        }

        private static void VerifyRoot()
        {
#if STAGING_SELFTEST
            if (!Directory.Exists(Root) || !Directory.Exists(PathInside("output")))
                throw new IOException("isolated test root absent");
#else
            if (!Directory.Exists(Root) || !Directory.Exists(PathInside("output")))
                throw new IOException("protected root and output must be precreated by installer");
            foreach (string p in new string[] {
                @"C:\", @"C:\Program Files", Path.GetDirectoryName(Root),
                Root, PathInside("output") })
            {
                FileAttributes a = File.GetAttributes(p);
                if ((a & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("reparse-point root denied");
                // Windows can grant Authenticated Users CreateDirectories /
                // AppendData on an ancestor without granting replacement of
                // an existing protected child. Deny structural rights on all
                // ancestors; require strictly no broad writes on custody roots.
                bool strict = String.Equals(p, Root, StringComparison.OrdinalIgnoreCase)
                    || String.Equals(p, PathInside("output"), StringComparison.OrdinalIgnoreCase);
                DirectorySecurity acl = Directory.GetAccessControl(p,
                    AccessControlSections.Access | AccessControlSections.Owner);
                RejectBroadAcl(acl, strict);
                if (String.Equals(p, Path.GetDirectoryName(Root), StringComparison.OrdinalIgnoreCase)
                    || strict) RequireTrustedOwner(acl);
                if (strict) RequireStrictCustodyAcl(acl);
            }
            string executable = System.Reflection.Assembly.GetExecutingAssembly().Location;
            if (!string.Equals(Path.GetFullPath(executable), PathInside("ObsessionStopCustodian.exe"),
                               StringComparison.OrdinalIgnoreCase))
                throw new IOException("executable outside protected service root");
            if ((File.GetAttributes(executable) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("executable reparse point denied");
            FileSecurity exeAcl = File.GetAccessControl(executable,
                AccessControlSections.Access | AccessControlSections.Owner);
            RejectBroadAcl(exeAcl, true);
            RequireTrustedOwner(exeAcl);
            RequireStrictCustodyAcl(exeAcl);
            string pinnedHash = File.ReadAllText(PathInside("binary.sha256"), Encoding.ASCII).Trim();
            if (!Digest.IsMatch(pinnedHash) || Sha256Hex(File.ReadAllBytes(executable)) != pinnedHash)
                throw new IOException("protected executable hash mismatch");
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                       @"SYSTEM\CurrentControlSet\Services\VeraObsessionStopCustodian", false))
            {
                if (key == null) throw new IOException("SCM service registration absent");
                string image = key.GetValue("ImagePath") as string;
                string account = key.GetValue("ObjectName") as string;
                string expected = "\"" + PathInside("ObsessionStopCustodian.exe") + "\"";
                if ((!string.Equals(image, expected, StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(image, PathInside("ObsessionStopCustodian.exe"),
                                      StringComparison.OrdinalIgnoreCase))
                    || account != "LocalSystem")
                    throw new IOException("SCM binpath or account drift");
            }
            // The installer must still verify effective rights under the
            // actual resident and bridge identities, not only ACE text.
#endif
        }

        private static void RequireTrustedOwner(FileSystemSecurity security)
        {
            SecurityIdentifier sid = security.GetOwner(typeof(SecurityIdentifier))
                as SecurityIdentifier;
            if (sid == null || !(sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
                || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)))
                throw new IOException("custody path owner is not SYSTEM or Administrators");
        }

        private static void RequireStrictCustodyAcl(FileSystemSecurity security)
        {
            // Checking only broad SIDs is insufficient: an ACL can grant
            // a specific untrusted user WRITE/FullControl while retaining
            // SYSTEM ownership. Protected custody permits exactly two
            // explicit trusted full-control ACEs and no inherited/deny ACEs.
            if (!security.AreAccessRulesProtected)
                throw new IOException("protected custody ACL inherits untrusted authority");
            AuthorizationRuleCollection rules = security.GetAccessRules(
                true, true, typeof(SecurityIdentifier));
            if (rules.Count != 2)
                throw new IOException("unexpected protected custody ACE count");
            bool system = false;
            bool administrators = false;
            foreach (AuthorizationRule rule in rules)
            {
                FileSystemAccessRule access = rule as FileSystemAccessRule;
                if (access == null || access.IsInherited
                    || access.AccessControlType != AccessControlType.Allow
                    || (access.FileSystemRights & FileSystemRights.FullControl)
                       != FileSystemRights.FullControl)
                    throw new IOException("protected custody contains nontrusted ACE");
                SecurityIdentifier sid = access.IdentityReference as SecurityIdentifier;
                if (sid == null)
                    throw new IOException("unresolved protected custody principal");
                if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid))
                {
                    if (system) throw new IOException("duplicate SYSTEM custody ACE");
                    system = true;
                }
                else if (sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                {
                    if (administrators)
                        throw new IOException("duplicate Administrators custody ACE");
                    administrators = true;
                }
                else throw new IOException("untrusted specific protected custody principal");
            }
            if (!system || !administrators)
                throw new IOException("protected custody missing trusted full-control ACE");
        }

        private static void RejectBroadAcl(FileSystemSecurity security, bool strict)
        {
            AuthorizationRuleCollection rules = security.GetAccessRules(true, true,
                                                                       typeof(SecurityIdentifier));
            foreach (AuthorizationRule rule in rules)
            {
                FileSystemAccessRule access = rule as FileSystemAccessRule;
                if (access == null || access.AccessControlType != AccessControlType.Allow)
                    continue;
                SecurityIdentifier sid = access.IdentityReference as SecurityIdentifier;
                if (sid == null) throw new IOException("unresolved host ACL principal");
                bool broad = sid.IsWellKnown(WellKnownSidType.WorldSid)
                    || sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid)
                    || sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid);
                FileSystemRights dangerous = FileSystemRights.WriteData
                    | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
                    | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
                if (strict)
                    dangerous |= FileSystemRights.AppendData | FileSystemRights.WriteAttributes
                        | FileSystemRights.WriteExtendedAttributes;
                if (broad && (access.FileSystemRights & dangerous) != 0)
                    throw new IOException("broad host ACL write/delete authority denied");
            }
        }

        private void LoadState()
        {
            lock (gate)
            {
                healthy = false;
                revoked.Clear();
                grants.Clear();
                VerifyRoot();
                string sidText = File.ReadAllText(PathInside("resident.sid"), Encoding.ASCII).Trim();
                residentSid = new SecurityIdentifier(sidText);
                if (residentSid.IsWellKnown(WellKnownSidType.WorldSid)
                    || residentSid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid)
                    || residentSid.IsWellKnown(WellKnownSidType.BuiltinUsersSid)
                    || residentSid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
                    || residentSid.IsWellKnown(WellKnownSidType.LocalSystemSid))
                    throw new IOException("resident pipe must bind a dedicated narrow SID");
                string stopPath = PathInside("stops.log");
                string grantPath = PathInside("grants.log");
                if (!File.Exists(stopPath) || !File.Exists(grantPath))
                    throw new IOException("explicitly initialized protected journals required");
#if !STAGING_SELFTEST
                foreach (string p in new string[] { PathInside("resident.sid"),
                           PathInside("binary.sha256"), stopPath, grantPath })
                {
                    if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("protected file reparse point denied");
                    FileSecurity acl = File.GetAccessControl(p,
                        AccessControlSections.Access | AccessControlSections.Owner);
                    RejectBroadAcl(acl, true);
                    RequireTrustedOwner(acl);
                    RequireStrictCustodyAcl(acl);
                }
#endif
                foreach (string row in File.ReadAllLines(stopPath, Encoding.ASCII))
                {
                    string[] p = row.Split('|');
                    if (p.Length != 3 || p[0] != "STOP" || !Generation.IsMatch(p[1])
                        || !IsTicks(p[2])) throw new IOException("corrupted STOP journal");
                    revoked.Add(p[1]);
                }
                foreach (string row in File.ReadAllLines(grantPath, Encoding.ASCII))
                {
                    string[] p = row.Split('|');
                    if (p.Length != 5 || p[0] != "GRANT" || !Generation.IsMatch(p[1])
                        || !ArtifactId.IsMatch(p[2]) || !Digest.IsMatch(p[3])
                        || !IsTicks(p[4])) throw new IOException("corrupted GRANT journal");
                    string key = p[1] + "|" + p[2];
                    Grant g = new Grant { Generation = p[1], Artifact = p[2],
                                          Digest = p[3], ExpiresUtcTicks = long.Parse(p[4]) };
                    Grant prior;
                    if (grants.TryGetValue(key, out prior)
                        && (prior.Digest != g.Digest || prior.ExpiresUtcTicks != g.ExpiresUtcTicks))
                        throw new IOException("divergent protected GRANT record");
                    grants[key] = g;
                }
                healthy = true;
            }
        }

        private static bool IsTicks(string s)
        {
            long v;
            return long.TryParse(s, out v) && v > DateTime.MinValue.Ticks && v <= DateTime.MaxValue.Ticks;
        }

        private static void DurableAppend(string file, string row)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(row + "\n");
            using (FileStream f = new FileStream(PathInside(file), FileMode.Append,
                       FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
            {
                f.Write(bytes, 0, bytes.Length);
                f.Flush(true);
            }
        }

        private string OperatorCommand(string message)
        {
            string[] p = message.Split('|');
            lock (gate)
            {
                if (!healthy) return "HOLD|JOURNAL_UNVERIFIED";
                if (p.Length == 3 && p[0] == "STOP" && Generation.IsMatch(p[1])
                    && p[2] == "V1")
                {
                    if (!revoked.Contains(p[1]))
                    {
                        try
                        {
                            DurableAppend("stops.log", "STOP|" + p[1] + "|" + DateTime.UtcNow.Ticks);
                        }
                        catch
                        {
                            // An ambiguous or torn durable STOP receipt must
                            // disable all publication until operator recovery.
                            healthy = false;
                            return "HOLD|STOP_DURABILITY_UNVERIFIED";
                        }
                        revoked.Add(p[1]);
                    }
                    return "STOPPED|" + p[1];
                }
                if (p.Length == 6 && p[0] == "GRANT" && Generation.IsMatch(p[1])
                    && ArtifactId.IsMatch(p[2]) && Digest.IsMatch(p[3]) && IsTicks(p[4])
                    && p[5] == "V1")
                {
                    if (revoked.Contains(p[1])) return "HOLD|GENERATION_REVOKED";
                    long expires = long.Parse(p[4]);
                    long now = DateTime.UtcNow.Ticks;
                    if (expires <= now || expires > now + TimeSpan.FromHours(1).Ticks)
                        return "HOLD|EXPIRY_INVALID";
                    string key = p[1] + "|" + p[2];
                    Grant prior;
                    if (grants.TryGetValue(key, out prior))
                    {
                        return prior.Digest == p[3] && prior.ExpiresUtcTicks == expires
                            ? "GRANT_EXISTS" : "HOLD|GRANT_DIVERGED";
                    }
                    try
                    {
                        DurableAppend("grants.log", "GRANT|" + p[1] + "|" + p[2] + "|" + p[3] + "|" + p[4]);
                    }
                    catch
                    {
                        healthy = false;
                        return "HOLD|GRANT_DURABILITY_UNVERIFIED";
                    }
                    grants[key] = new Grant { Generation = p[1], Artifact = p[2],
                                               Digest = p[3], ExpiresUtcTicks = expires };
                    return "GRANTED|" + p[2];
                }
                return "HOLD|UNRECOGNIZED_OPERATOR_COMMAND";
            }
        }

        private static string Sha256Hex(byte[] input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(input);
                StringBuilder sb = new StringBuilder(64);
                foreach (byte b in hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        private string PublishCommand(string message)
        {
            string[] p = message.Split('|');
            if (p.Length != 5 || p[0] != "PUBLISH"
                || !Generation.IsMatch(p[1]) || !ArtifactId.IsMatch(p[2]) || p[4] != "V1")
                return "HOLD|INVALID_PUBLISH_REQUEST";
            byte[] payload;
            try { payload = Convert.FromBase64String(p[3]); }
            catch (FormatException) { return "HOLD|INVALID_BASE64"; }
            if (payload.Length < 1 || payload.Length > 4096)
                return "HOLD|PAYLOAD_BOUND";
            if (!IsSyntheticHandoff(payload, p[1], p[2])) return "HOLD|NOT_SYNTHETIC_HANDOFF";
            string hash = Sha256Hex(payload);
            lock (gate)
            {
                if (!healthy || revoked.Contains(p[1])) return "HOLD|STOP_ACTIVE_OR_UNVERIFIED";
                Grant grant;
                if (!grants.TryGetValue(p[1] + "|" + p[2], out grant))
                    return "HOLD|NO_PROTECTED_OWNER_GRANT";
                if (DateTime.UtcNow.Ticks >= grant.ExpiresUtcTicks || grant.Digest != hash)
                    return "HOLD|GRANT_EXPIRED_OR_DIGEST_MISMATCH";
                string output = PathInside("output");
                string target = Path.Combine(output, p[2] + ".json");
                if (File.Exists(target))
                {
                    byte[] old = File.ReadAllBytes(target);
                    return Sha256Hex(old) == hash ? "ALREADY_PRESENT|" + p[2]
                        : "HOLD|DIVERGENT_PROTECTED_ARTIFACT";
                }
                string temporary = Path.Combine(output, "." + p[2] + "." + Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    using (FileStream f = new FileStream(temporary, FileMode.CreateNew,
                               FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                    {
                        f.Write(payload, 0, payload.Length);
                        f.Flush(true);
                    }
                    File.Move(temporary, target); // atomic no-replace on same NTFS volume
                }
                finally
                {
                    if (File.Exists(temporary)) File.Delete(temporary);
                }
                return "PUBLISHED|" + p[2];
            }
        }

        private static bool HasExactKeys(Dictionary<string, object> fields, string[] required)
        {
            if (fields == null || fields.Count != required.Length) return false;
            foreach (string key in required)
                if (!fields.ContainsKey(key)) return false;
            return true;
        }

        // JavaScriptSerializer materializes objects as dictionaries, potentially
        // losing duplicate properties before application validation. Walk the
        // JSON tokens first and reject duplicate keys in EVERY object, including
        // nested proposal/salience/provenance objects. Canonical resident keys
        // are unescaped; reject escaped object keys so two spellings cannot
        // collapse into one semantic key after parser normalization.
        private sealed class UniqueJsonScanner
        {
            private readonly string source;
            private int position;

            private UniqueJsonScanner(string json) { source = json; }

            public static bool Valid(string json)
            {
                try
                {
                    UniqueJsonScanner parser = new UniqueJsonScanner(json);
                    parser.Value(0);
                    parser.Space();
                    return parser.position == json.Length;
                }
                catch (FormatException) { return false; }
            }

            private void Space()
            {
                while (position < source.Length && (source[position] == ' '
                    || source[position] == '\t' || source[position] == '\r'
                    || source[position] == '\n')) position++;
            }

            private bool Take(char expected)
            {
                if (position >= source.Length || source[position] != expected) return false;
                position++;
                return true;
            }

            private void Need(char expected)
            {
                if (!Take(expected)) throw new FormatException("invalid JSON delimiter");
            }

            private static bool Digit(char c) { return c >= '0' && c <= '9'; }
            private static bool Hex(char c)
            {
                return Digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            }

            private string Quoted(bool key)
            {
                Need('"');
                int start = position;
                while (position < source.Length)
                {
                    char c = source[position++];
                    if (c == '"') return source.Substring(start, position - start - 1);
                    if (c < 32) throw new FormatException("unescaped control character");
                    if (c != '\\') continue;
                    if (key || position >= source.Length)
                        throw new FormatException("escaped JSON key denied");
                    char escape = source[position++];
                    if (escape == 'u')
                    {
                        for (int i = 0; i < 4; i++)
                            if (position >= source.Length || !Hex(source[position++]))
                                throw new FormatException("invalid unicode escape");
                    }
                    else if (escape != '"' && escape != '\\' && escape != '/'
                        && escape != 'b' && escape != 'f' && escape != 'n'
                        && escape != 'r' && escape != 't')
                        throw new FormatException("invalid JSON escape");
                }
                throw new FormatException("unterminated JSON string");
            }

            private void Literal(string word)
            {
                if (source.Length - position < word.Length
                    || String.CompareOrdinal(source, position, word, 0, word.Length) != 0)
                    throw new FormatException("invalid JSON literal");
                position += word.Length;
            }

            private void Number()
            {
                Take('-');
                if (!Take('0'))
                {
                    if (position >= source.Length || source[position] < '1'
                        || source[position] > '9') throw new FormatException("invalid JSON number");
                    while (position < source.Length && Digit(source[position])) position++;
                }
                if (Take('.'))
                {
                    if (position >= source.Length || !Digit(source[position]))
                        throw new FormatException("invalid JSON decimal");
                    while (position < source.Length && Digit(source[position])) position++;
                }
                if (Take('e') || Take('E'))
                {
                    if (!Take('+')) Take('-');
                    if (position >= source.Length || !Digit(source[position]))
                        throw new FormatException("invalid JSON exponent");
                    while (position < source.Length && Digit(source[position])) position++;
                }
            }

            private void Value(int depth)
            {
                if (depth > 32) throw new FormatException("JSON nesting bound exceeded");
                Space();
                if (position >= source.Length) throw new FormatException("missing JSON value");
                char c = source[position];
                if (c == '{')
                {
                    position++;
                    HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
                    Space();
                    if (Take('}')) return;
                    do
                    {
                        Space();
                        string key = Quoted(true);
                        if (!seen.Add(key)) throw new FormatException("duplicate JSON key");
                        Space(); Need(':');
                        Value(depth + 1);
                        Space();
                        if (Take('}')) return;
                        Need(',');
                    } while (true);
                }
                if (c == '[')
                {
                    position++;
                    Space();
                    if (Take(']')) return;
                    do
                    {
                        Value(depth + 1);
                        Space();
                        if (Take(']')) return;
                        Need(',');
                    } while (true);
                }
                if (c == '"') { Quoted(false); return; }
                if (c == 't') { Literal("true"); return; }
                if (c == 'f') { Literal("false"); return; }
                if (c == 'n') { Literal("null"); return; }
                Number();
            }
        }

        private static bool IsFalse(Dictionary<string, object> fields, string key)
        {
            object value;
            return fields.TryGetValue(key, out value) && value is bool && !(bool)value;
        }

        private static bool IsFiniteNumber(object value, double min, double max)
        {
            if (!(value is int || value is long || value is double || value is decimal))
                return false;
            double n = Convert.ToDouble(value, CultureInfo.InvariantCulture);
            return !double.IsNaN(n) && !double.IsInfinity(n) && n > min && n <= max;
        }

        private static bool IsSyntheticHandoff(byte[] payload, string generation, string artifactId)
        {
            try
            {
                string json = new UTF8Encoding(false, true).GetString(payload);
                if (json.IndexOf('\0') >= 0 || json.IndexOf('\r') >= 0
                    || !json.EndsWith("\n", StringComparison.Ordinal)
                    || json.EndsWith("\n\n", StringComparison.Ordinal)) return false;
                if (!UniqueJsonScanner.Valid(json)) return false;
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                serializer.MaxJsonLength = 4096;
                Dictionary<string, object> fields = serializer.DeserializeObject(json)
                    as Dictionary<string, object>;
                if (!HasExactKeys(fields, HandoffKeys)) return false;
                object schema, scope, digest, proposal;
                if (!fields.TryGetValue("schema", out schema)
                    || (schema as string) != "initiative.local-handoff.v1"
                    || !fields.TryGetValue("scope", out scope)
                    || (scope as string) != "LOCAL_SYNTHETIC_HANDOFF_ONLY"
                    || !IsFalse(fields, "delivery_verified")
                    || !IsFalse(fields, "contact_authorized")
                    || !fields.TryGetValue("proposal_digest", out digest)
                    || !(digest is string) || !TypedDigest.IsMatch((string)digest)
                    || !fields.TryGetValue("proposal", out proposal)) return false;

                Dictionary<string, object> child = proposal as Dictionary<string, object>;
                if (!HasExactKeys(child, ProposalKeys)) return false;
                string typedArtifact = "sha256:" + artifactId;
                object proposalId, idempotencyKey, childGeneration, childGoalDigest;
                object origin, category, targetClass, modelSchema, proposeOnly;
                object evidence, provider, createdAt, expiresAt, ttl, message, reason;
                object salience, provenance;
                return child.TryGetValue("schema", out modelSchema)
                    && (modelSchema as string) == "initiative.proposal.v1"
                    && child.TryGetValue("proposal_id", out proposalId)
                    && (proposalId as string) == typedArtifact
                    && child.TryGetValue("idempotency_key", out idempotencyKey)
                    && (idempotencyKey as string) == typedArtifact
                    && child.TryGetValue("generation", out childGeneration)
                    && (childGeneration as string) == generation
                    && child.TryGetValue("goal_digest", out childGoalDigest)
                    && childGoalDigest is string && TypedDigest.IsMatch((string)childGoalDigest)
                    && child.TryGetValue("origin", out origin)
                    && (origin as string) == "OBSESSION_RESIDENT_SYNTHETIC_V1"
                    && child.TryGetValue("category", out category)
                    && (category as string) == "OWNER_DIRECTED_SYNTHETIC_DIAGNOSTIC"
                    && child.TryGetValue("target_class", out targetClass)
                    && (targetClass as string) == "SYNTHETIC_LOCAL_ONLY"
                    && child.TryGetValue("propose_only", out proposeOnly)
                    && proposeOnly is bool && (bool)proposeOnly
                    && IsFalse(child, "execution_authorized")
                    && IsFalse(child, "contact_authorized")
                    && IsFalse(child, "delivery_verified")
                    && child.TryGetValue("provider_evidence", out provider)
                    && provider is string
                    && child.TryGetValue("evidence_class", out evidence)
                    && (evidence as string) == (provider as string)
                    && child.TryGetValue("created_at", out createdAt)
                    && IsFiniteNumber(createdAt, -1.0, double.MaxValue)
                    && child.TryGetValue("expires_at", out expiresAt)
                    && IsFiniteNumber(expiresAt, 0.0, double.MaxValue)
                    && child.TryGetValue("ttl_seconds", out ttl)
                    && IsFiniteNumber(ttl, 0.0, 86400.0)
                    && child.TryGetValue("message", out message)
                    && message is string && ((string)message).Length <= 512
                    && !String.IsNullOrWhiteSpace((string)message)
                    && child.TryGetValue("reason", out reason)
                    && reason is string && ((string)reason).Length <= 256
                    && !String.IsNullOrWhiteSpace((string)reason)
                    && child.TryGetValue("salience", out salience)
                    && salience is Dictionary<string, object>
                    && child.TryGetValue("provenance", out provenance)
                    && provenance is Dictionary<string, object>;
            }
            catch (Exception) { return false; }
        }

        private static byte[] ReadFrame(Stream stream)
        {
            // One monotonic deadline for the COMPLETE frame, including the
            // length header and payload. A per-read timeout permits an
            // attacker to drip one byte every 2.9 seconds indefinitely.
            long deadline = Stopwatch.GetTimestamp() + Stopwatch.Frequency * 3;
            byte[] len = new byte[4];
            ReadExact(stream, len, 0, 4, deadline);
            int n = (len[0] << 24) | (len[1] << 16) | (len[2] << 8) | len[3];
            if (n < 1 || n > 8192) throw new IOException("frame too large or empty");
            byte[] b = new byte[n];
            ReadExact(stream, b, 0, n, deadline);
            return b;
        }

        private static int RemainingMilliseconds(long deadline)
        {
            long remaining = deadline - Stopwatch.GetTimestamp();
            if (remaining <= 0) throw new IOException("whole-frame pipe deadline");
            return (int)Math.Min(3000L, Math.Max(1L,
                remaining * 1000L / Stopwatch.Frequency));
        }

        private static void ReadExact(Stream s, byte[] b, int offset, int count,
                                      long deadline)
        {
            while (count > 0)
            {
                int timeout = RemainingMilliseconds(deadline);
                IAsyncResult pending = s.BeginRead(b, offset, count, null, null);
                int got;
                WaitHandle completed = pending.AsyncWaitHandle;
                if (!completed.WaitOne(timeout))
                {
                    SettleExpiredPipeIo(s, pending, completed, false);
                    throw new IOException("whole-frame pipe deadline");
                }
                try { got = s.EndRead(pending); }
                finally { completed.Close(); }
                if (got <= 0) throw new EndOfStreamException();
                offset += got;
                count -= got;
            }
        }

        private static void SettleExpiredPipeIo(Stream stream, IAsyncResult pending,
                                                WaitHandle completion, bool writing)
        {
            // A timed-out APM operation remains live. Closing AsyncWaitHandle
            // before PipeStream.AsyncPSCallback signals it can terminate the
            // process with ObjectDisposedException (observed on Windows).
            PipeStream pipe = stream as PipeStream;
            if (pipe == null)
                throw new FatalPipeIoException("timed-out operation is not a pipe");
            bool requested = CancelIoEx(pipe.SafePipeHandle, IntPtr.Zero);
            int error = Marshal.GetLastWin32Error();
            // ERROR_NOT_FOUND: the I/O already completed at cancellation time.
            if (!requested && error != 1168)
                throw new FatalPipeIoException("overlapped pipe cancellation failed");
            if (!completion.WaitOne(1500))
                throw new FatalPipeIoException("overlapped pipe cancellation did not settle");
            try
            {
                if (writing) stream.EndWrite(pending);
                else stream.EndRead(pending);
            }
            catch (IOException) { /* Expected ERROR_OPERATION_ABORTED. */ }
            catch (OperationCanceledException) { /* Canceled after deadline. */ }
            finally { completion.Close(); }
        }

        private static void WriteFrame(Stream s, string message)
        {
            long deadline = Stopwatch.GetTimestamp() + Stopwatch.Frequency * 3;
            byte[] b = new UTF8Encoding(false, true).GetBytes(message);
            if (b.Length > 8192) throw new IOException("response too long");
            byte[] n = new byte[] { (byte)(b.Length >> 24), (byte)(b.Length >> 16),
                                     (byte)(b.Length >> 8), (byte)b.Length };
            WriteWithDeadline(s, n, deadline);
            WriteWithDeadline(s, b, deadline);
            s.Flush();
        }

        private static string ResponseReadAck(string response)
        {
            // The response frame itself is not proof of delivery: on Windows,
            // DisconnectNamedPipe discards unread data buffered for the client,
            // while PipeStream.Flush does not wait for the client to consume it.
            // Bind the application's read acknowledgment to the exact reply.
            return "ACK|" + Sha256Hex(new UTF8Encoding(false, true).GetBytes(response))
                + "|V1";
        }

        private static bool AwaitResponseReadAck(Stream s, string response)
        {
            // The peer acknowledges only *after* reading the entire reply.
            // An absent/invalid ACK is NOT a successful delivery receipt and
            // never extends the 3-second whole-frame deadline indefinitely.
            try
            {
                return String.Equals(DecodeUtf8(ReadFrame(s)), ResponseReadAck(response),
                                     StringComparison.Ordinal);
            }
            catch (FatalPipeIoException) { throw; }
            catch (IOException) { return false; }
            catch (DecoderFallbackException) { return false; }
        }

        private static void CompletePendingConnectOnStop(NamedPipeServerStream pipe,
                                                          IAsyncResult pending)
        {
            // EndWaitForConnection owns/closes its asynchronous wait event;
            // every BeginWaitForConnection must settle before pipe disposal.
            WaitHandle completion = pending.AsyncWaitHandle;
            if (!completion.WaitOne(0))
            {
                bool requested = CancelIoEx(pipe.SafePipeHandle, IntPtr.Zero);
                int error = Marshal.GetLastWin32Error();
                if (!requested && error != 1168)
                    throw new FatalPipeIoException("pending connect cancellation failed");
                if (!completion.WaitOne(1500))
                    throw new FatalPipeIoException("pending connect cancellation did not settle");
            }
            try { pipe.EndWaitForConnection(pending); }
            catch (IOException) { /* ERROR_OPERATION_ABORTED or peer dropped. */ }
            catch (OperationCanceledException) { /* Expected cancellation. */ }
        }

        private static void WriteWithDeadline(Stream stream, byte[] buffer,
                                              long deadline)
        {
            int timeout = RemainingMilliseconds(deadline);
            IAsyncResult pending = stream.BeginWrite(buffer, 0, buffer.Length, null, null);
            WaitHandle completed = pending.AsyncWaitHandle;
            if (!completed.WaitOne(timeout))
            {
                SettleExpiredPipeIo(stream, pending, completed, true);
                throw new IOException("whole-frame pipe deadline");
            }
            try { stream.EndWrite(pending); }
            finally { completed.Close(); }
        }

        private static string DecodeUtf8(byte[] b)
        {
            return new UTF8Encoding(false, true).GetString(b);
        }

        private PipeSecurity PipeAcl(bool operatorAccess)
        {
            PipeSecurity acl = new PipeSecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
            acl.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
#if STAGING_PIPE_TEST
            // Test-only loopback identity on BOTH isolated pipe endpoints.
            // Never included in a production binary.
            acl.AddAccessRule(new PipeAccessRule(
                WindowsIdentity.GetCurrent().User,
                PipeAccessRights.FullControl, AccessControlType.Allow));
#endif
            if (!operatorAccess)
                acl.AddAccessRule(new PipeAccessRule(residentSid, PipeAccessRights.ReadWrite,
                                                     AccessControlType.Allow));
            return acl;
        }

        private NamedPipeServerStream CreateExclusivePipe(bool operatorAccess)
        {
            byte[] securityDescriptor = PipeAcl(operatorAccess).GetSecurityDescriptorBinaryForm();
            IntPtr descriptor = Marshal.AllocHGlobal(securityDescriptor.Length);
            try
            {
                Marshal.Copy(securityDescriptor, 0, descriptor, securityDescriptor.Length);
                SecurityAttributes attributes = new SecurityAttributes {
                    Length = Marshal.SizeOf(typeof(SecurityAttributes)),
                    SecurityDescriptor = descriptor,
                    InheritHandle = false
                };
                string fullName = @"\\.\pipe\" + (operatorAccess ? OperatorPipe : PublishPipe);
                SafePipeHandle handle = CreateNamedPipe(fullName,
                    PipeAccessDuplex | FileFlagOverlapped | FileFlagFirstInstance,
                    PipeRejectRemoteClients, 1, 4096, 4096, 3000, ref attributes);
                if (handle == null || handle.IsInvalid)
                {
                    int code = Marshal.GetLastWin32Error();
                    if (handle != null) handle.Dispose();
                    throw new Win32Exception(code, "exclusive STOP pipe reservation failed");
                }
                try
                {
                    return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
                }
                catch
                {
                    handle.Dispose();
                    throw;
                }
            }
            finally { Marshal.FreeHGlobal(descriptor); }
        }

        private static void DisconnectOrFail(NamedPipeServerStream pipe)
        {
            try
            {
                // Microsoft .NET Framework permits Disconnect from BOTH
                // Connected and Broken states. After the client closes,
                // IsConnected becomes false while the server handle remains
                // in Broken state; skipping Disconnect poisons the retained
                // first-instance handle's next BeginWaitForConnection.
                pipe.Disconnect();
            }
            catch (IOException)
            {
                // If the required state transition fails, reusing this
                // first-instance handle would report false service health.
                throw new FatalPipeIoException("pipe could not transition to Disconnected state");
            }
            catch (InvalidOperationException)
            {
                throw new FatalPipeIoException("pipe state invalid at required disconnect");
            }
        }

        private void ServePipe(bool operatorAccess, NamedPipeServerStream pipe)
        {
            try
            {
                // Keep each first-instance pipe handle for the service lifetime.
                // Reopening it by name between requests creates a squatting gap.
                using (pipe)
                {
#if STAGING_PIPE_TEST
                    int stageConnections = 0;
#endif
                    while (running)
                    {
                        IAsyncResult pending = pipe.BeginWaitForConnection(null, null);
                        while (running && !pending.AsyncWaitHandle.WaitOne(250)) { }
                        if (!running)
                        {
                            CompletePendingConnectOnStop(pipe, pending);
                            break;
                        }
                        pipe.EndWaitForConnection(pending);
#if STAGING_PIPE_TEST
                        stageConnections++;
                        Console.WriteLine("PIPE_DIAGNOSTIC server_connected="
                            + (operatorAccess ? "operator" : "publish")
                            + ";index=" + stageConnections);
#endif
                        string answer;
                        bool peerStillPresent = true;
                        try
                        {
                            string request = DecodeUtf8(ReadFrame(pipe));
                            answer = operatorAccess ? OperatorCommand(request) : PublishCommand(request);
                        }
                        catch (FatalPipeIoException) { throw; }
                        catch (EndOfStreamException)
                        {
                            // Abruptly disconnected clients have not submitted
                            // a complete request and cannot consume any reply.
                            // Writing a meaningless HOLD to the abandoned
                            // handle and awaiting its ACK stalls reconnection.
                            peerStillPresent = false;
                            answer = null;
#if STAGING_PIPE_TEST
                            Console.WriteLine("PIPE_DIAGNOSTIC disconnected_mid_request="
                                + (operatorAccess ? "operator" : "publish")
                                + ";index=" + stageConnections);
#endif
                        }
                        catch (Exception) { answer = "HOLD|MALFORMED_OR_FAILED"; }
                        if (peerStillPresent)
                        {
                            try
                            {
                                WriteFrame(pipe, answer);
#if STAGING_PIPE_TEST
                                bool acknowledged = AwaitResponseReadAck(pipe, answer);
                                Console.WriteLine("PIPE_DIAGNOSTIC response_read_ack="
                                    + (acknowledged ? "yes" : "no") + ";index=" + stageConnections);
#else
                                AwaitResponseReadAck(pipe, answer);
#endif
                            }
                            catch (FatalPipeIoException) { throw; }
                            catch (IOException)
                            {
                                // The peer may close after command processing.
                                // Preserve the reserved first-instance handle.
                            }
                        }
                        if (!running) break;
                        DisconnectOrFail(pipe);
#if STAGING_PIPE_TEST
                        Console.WriteLine("PIPE_DIAGNOSTIC server_disconnected="
                            + (operatorAccess ? "operator" : "publish")
                            + ";index=" + stageConnections
                            + ";is_connected=" + pipe.IsConnected);
#endif
                    }
                }
            }
            catch (Exception error)
            {
                // A lost exclusive handle is a fatal service-integrity failure;
                // never expose a RUNNING service with an unowned pipe name.
#if STAGING_PIPE_TEST
                Console.Error.WriteLine("PIPE_FATAL listener="
                    + (operatorAccess ? "operator" : "publish")
                    + ";type=" + error.GetType().FullName
                    + ";message=" + error.Message.Replace('\r', ' ').Replace('\n', ' ')
                    + ";stack=" + error.StackTrace);
#endif
                bool unexpected;
                lock (gate)
                {
                    unexpected = running;
                    healthy = false;
                    running = false;
                }
                if (unexpected || error is FatalPipeIoException)
                    Environment.FailFast("STOP custodian pipe integrity lost", error);
            }
        }

        protected override void OnStart(string[] args)
        {
            LoadState(); // fail before pipes expose any publication capability
            NamedPipeServerStream operatorPipe = null;
            NamedPipeServerStream publishPipe = null;
            bool operatorStarted = false;
            bool publishStarted = false;
            try
            {
                // Reserve BOTH names synchronously before SCM reports RUNNING.
                // A pre-bound same-name pipe makes startup fail closed.
                operatorPipe = CreateExclusivePipe(true);
                publishPipe = CreateExclusivePipe(false);
                running = true;
                NamedPipeServerStream capturedOperator = operatorPipe;
                NamedPipeServerStream capturedPublish = publishPipe;
                operatorThread = new Thread(() => ServePipe(true, capturedOperator));
                publishThread = new Thread(() => ServePipe(false, capturedPublish));
                operatorThread.IsBackground = true;
                publishThread.IsBackground = true;
                operatorThread.Start();
                operatorStarted = true;
                publishThread.Start();
                publishStarted = true;
            }
            catch
            {
                lock (gate) { healthy = false; running = false; }
                // Started workers own their pipe handles and pending APM wait.
                // Wait for their cancellation/EndWait path before any disposal.
                bool operatorDrained = !operatorStarted || operatorThread.Join(10000);
                bool publishDrained = !publishStarted || publishThread.Join(10000);
                if (!operatorDrained || !publishDrained)
                    Environment.FailFast("STOP custodian startup worker drain unverified");
                if (!operatorStarted && operatorPipe != null) operatorPipe.Dispose();
                if (!publishStarted && publishPipe != null) publishPipe.Dispose();
                throw;
            }
        }

        protected override void OnStop()
        {
            // Commands hold gate through durable side effects. Acquiring it
            // before SCM stop-ack prevents an in-flight PUBLISH from committing
            // AFTER the service has acknowledged stopping.
            lock (gate) { healthy = false; running = false; }
            bool operatorDrained = operatorThread == null || operatorThread.Join(10000);
            bool publishDrained = publishThread == null || publishThread.Join(10000);
            if (!operatorDrained || !publishDrained)
                throw new IOException("STOP custodian worker drain unverified");
        }

#if STAGING_PIPE_TEST
        private static string StageExchange(string pipeName, string request)
        {
            using (NamedPipeClientStream client = new NamedPipeClientStream(
                ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                client.Connect(3000);
                WriteFrame(client, request);
                string response = DecodeUtf8(ReadFrame(client));
                WriteFrame(client, ResponseReadAck(response));
                return response;
            }
        }

        private static string StageBadLength(string pipeName)
        {
            using (NamedPipeClientStream client = new NamedPipeClientStream(
                ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                client.Connect(3000);
                // A frame larger than the source's 8192-byte ceiling.
                byte[] oversize = new byte[] { 0, 0, 32, 1 };
                client.Write(oversize, 0, oversize.Length);
                client.Flush();
                string response = DecodeUtf8(ReadFrame(client));
                WriteFrame(client, ResponseReadAck(response));
                return response;
            }
        }

        private static void StageAbruptDisconnectBurst(string pipeName, int count)
        {
            // Close each client after writing an incomplete length prefix.
            // The retained first-instance listener must recover without
            // losing its name or violating asynchronous callback lifetime.
            Stopwatch elapsed = Stopwatch.StartNew();
            for (int i = 0; i < count; i++)
            {
                using (NamedPipeClientStream client = new NamedPipeClientStream(
                    ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
                {
                    try { client.Connect(3000); }
                    catch (System.TimeoutException)
                    {
                        Console.Error.WriteLine("PIPE_TEST_FAILURE abrupt_disconnect_connect"
                            + "_index=" + i + ";elapsed_ms=" + elapsed.ElapsedMilliseconds);
                        throw;
                    }
                    byte[] incomplete = new byte[] { 0, 0 };
                    client.Write(incomplete, 0, incomplete.Length);
                    client.Flush();
                }
            }
            Console.WriteLine("PIPE_TEST abrupt_disconnects=" + count);
            Console.WriteLine("PIPE_DIAGNOSTIC abrupt_disconnect_duration_ms="
                + elapsed.ElapsedMilliseconds);
        }

        private static string StageDripTimeout(string pipeName)
        {
            using (NamedPipeClientStream client = new NamedPipeClientStream(
                ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                client.Connect(3000);
                // Header promises a ten-byte request, but the client provides
                // only the first two payload bytes. The server must issue HOLD
                // after its single whole-frame 3-second deadline.
                byte[] partial = new byte[] { 0, 0, 0, 10, (byte)'S', (byte)'T' };
                client.Write(partial, 0, partial.Length);
                client.Flush();
                Thread.Sleep(3600);
                // Windows named-pipe Disconnect can discard a queued HOLD
                // before the client consumes it. A closed pipe is a valid
                // fail-closed transport outcome, but not a positive reply.
                try
                {
                    string response = DecodeUtf8(ReadFrame(client));
                    WriteFrame(client, ResponseReadAck(response));
                    return response;
                }
                catch (EndOfStreamException) { return "CLOSED_WITHOUT_ACK"; }
                catch (IOException error)
                {
                    if (error.Message == "whole-frame pipe deadline") throw;
                    return "CLOSED_WITHOUT_ACK";
                }
            }
        }

        private static void StageRequire(string label, string actual, string expected)
        {
            Console.WriteLine("PIPE_TEST " + label + "=" + actual);
            if (!String.Equals(actual, expected, StringComparison.Ordinal))
            {
                Console.Error.WriteLine("PIPE_TEST_FAILURE " + label + " expected=" + expected);
                Environment.ExitCode = 1;
            }
        }

        private static void StageRequireTimeoutDenial(string actual)
        {
            Console.WriteLine("PIPE_TEST whole_frame_timeout=" + actual);
            if (actual != "HOLD|MALFORMED_OR_FAILED" && actual != "CLOSED_WITHOUT_ACK")
            {
                Console.Error.WriteLine("PIPE_TEST_FAILURE whole_frame_timeout"
                    + " unexpected_ack=" + actual);
                Environment.ExitCode = 1;
            }
        }

        private static void StagePipeExercise(string sourcePayload, string originalGeneration,
                                              string originalTypedArtifact)
        {
            string generation = "staging_pipe_generation_0002";
            string artifact = new string('d', 64);
            string payloadText = sourcePayload.Replace(originalGeneration, generation)
                .Replace(originalTypedArtifact, "sha256:" + artifact);
            byte[] payload = Encoding.UTF8.GetBytes(payloadText);
            string digest = Sha256Hex(payload);
            string publish = "PUBLISH|" + generation + "|" + artifact + "|"
                + Convert.ToBase64String(payload) + "|V1";
            string grant = "GRANT|" + generation + "|" + artifact + "|" + digest
                + "|" + DateTime.UtcNow.AddMinutes(2).Ticks + "|V1";
            // The same production command/handler code below runs through
            // actual Windows BYTE-mode named pipes, without any SCM service.
            StopCustodian stage = new StopCustodian();
            stage.OnStart(new string[0]);
            try
            {
                StageRequire("publish_before_grant", StageExchange(PublishPipe, publish),
                             "HOLD|NO_PROTECTED_OWNER_GRANT");
                StageRequire("operator_command_on_publish_pipe",
                             StageExchange(PublishPipe, "STOP|" + generation + "|V1"),
                             "HOLD|INVALID_PUBLISH_REQUEST");
                StageRequire("publish_command_on_operator_pipe",
                             StageExchange(OperatorPipe, publish),
                             "HOLD|UNRECOGNIZED_OPERATOR_COMMAND");
                StageRequire("invalid_expiry", StageExchange(OperatorPipe,
                    "GRANT|" + generation + "|" + artifact + "|" + digest
                    + "|" + DateTime.UtcNow.AddHours(2).Ticks + "|V1"),
                    "HOLD|EXPIRY_INVALID");
                StageRequire("bad_frame_length", StageBadLength(PublishPipe),
                             "HOLD|MALFORMED_OR_FAILED");
                StageRequireTimeoutDenial(StageDripTimeout(PublishPipe));
                StageRequire("post_timeout_recovery", StageExchange(PublishPipe, publish),
                             "HOLD|NO_PROTECTED_OWNER_GRANT");
                StageAbruptDisconnectBurst(PublishPipe, 100);
                StageRequire("post_disconnect_burst_recovery", StageExchange(PublishPipe, publish),
                             "HOLD|NO_PROTECTED_OWNER_GRANT");
                StageRequire("grant", StageExchange(OperatorPipe, grant), "GRANTED|" + artifact);
                StageRequire("publish", StageExchange(PublishPipe, publish), "PUBLISHED|" + artifact);
                StageRequire("idempotent_publish", StageExchange(PublishPipe, publish),
                             "ALREADY_PRESENT|" + artifact);
                StageRequire("stop", StageExchange(OperatorPipe,
                             "STOP|" + generation + "|V1"), "STOPPED|" + generation);
                StageRequire("publish_after_stop", StageExchange(PublishPipe, publish),
                             "HOLD|STOP_ACTIVE_OR_UNVERIFIED");
                StageRequire("grant_after_stop", StageExchange(OperatorPipe, grant),
                             "HOLD|GENERATION_REVOKED");
                string output = PathInside("output");
                if (!File.Exists(Path.Combine(output, artifact + ".json")))
                {
                    Console.Error.WriteLine("PIPE_TEST_FAILURE no isolated synthetic output");
                    Environment.ExitCode = 1;
                }
                Console.WriteLine("PIPE_TEST_MODE=STAGING_ONLY;PIPE_NAMESPACE=PROCESS_LOCAL"
                    + ";CONTACT_DISABLED=true;CROSS_IDENTITY_ACL=UNVERIFIED");
            }
            finally { stage.OnStop(); }
        }

        private static void StageCollisionProbe()
        {
            // Reserve operator name first, then prove patched OnStart fails
            // closed rather than falsely acknowledging readiness.
            StopCustodian stage = new StopCustodian();
            stage.LoadState();
            bool rejected = false;
            string diagnostic = "UNATTEMPTED";
            using (NamedPipeServerStream squatter = stage.CreateExclusivePipe(true))
            {
                try { stage.OnStart(new string[0]); }
                catch (Win32Exception ex)
                {
                    diagnostic = "WIN32_" + ex.NativeErrorCode;
                    rejected = ex.NativeErrorCode == 5 || ex.NativeErrorCode == 231;
                }
                catch (Exception ex) { diagnostic = ex.GetType().FullName; }
                if (!rejected)
                {
                    Console.Error.WriteLine("COLLISION_FAIL_CLOSED=FAIL;diagnostic=" + diagnostic);
                    Environment.ExitCode = 2;
                }
                else if (stage.healthy || stage.running)
                {
                    Console.Error.WriteLine("COLLISION_FAIL_CLOSED=FAIL;healthy_or_running");
                    Environment.ExitCode = 2;
                }
                else
                {
                    Console.WriteLine("COLLISION_FAIL_CLOSED=PASS;diagnostic=" + diagnostic
                        + ";START_DENIED_BEFORE_SCM_ACK=true;STAGING_ONLY=true");
                }
                if (stage.running) stage.OnStop();
            }
        }

        private static void StageIdentityWindow()
        {
            StopCustodian stage = new StopCustodian();
            stage.OnStart(new string[0]);
            try
            {
                Console.WriteLine("IDENTITY_WINDOW stage_operator_pipe=\\\\.\\pipe\\" + OperatorPipe);
                Console.WriteLine("IDENTITY_WINDOW stage_publish_pipe=\\\\.\\pipe\\" + PublishPipe);
                Console.WriteLine("IDENTITY_WINDOW current_user_sid="
                    + WindowsIdentity.GetCurrent().User.Value);
                Console.WriteLine("IDENTITY_WINDOW seconds=45"
                    + ";SECONDARY_USER_MUST_NOT_BE_ADMIN_OR_SYSTEM"
                    + ";CROSS_IDENTITY_ACL=UNVERIFIED_UNTIL_PROBED");
                Thread.Sleep(45000);
            }
            finally { stage.OnStop(); }
        }

        private static void StageIdleStopStress()
        {
            // Exercise the BeginWaitForConnection -> OnStop cancellation path,
            // distinct from an existing stop-after-command test.
            for (int i = 0; i < 40; i++)
            {
                StopCustodian stage = new StopCustodian();
                stage.OnStart(new string[0]);
                Thread.Sleep(20);
                stage.OnStop();
            }
            Console.WriteLine("PIPE_TEST idle_stop_restarts=40;"
                + "PENDING_CONNECT_END_REQUIRED=true;STAGING_ONLY=true");
        }
#endif
        public static void Main()
        {
#if STAGING_SELFTEST
            string folder = PathInside("output");
            Directory.CreateDirectory(folder);
            File.WriteAllText(PathInside("resident.sid"), "S-1-5-21-1-2-3-1001", Encoding.ASCII);
            File.WriteAllText(PathInside("stops.log"), string.Empty, Encoding.ASCII);
            File.WriteAllText(PathInside("grants.log"), string.Empty, Encoding.ASCII);
            StopCustodian initial = new StopCustodian();
            initial.LoadState();
            string generation = "staging_generation_0001";
            string artifact = new string('a', 64);
            string typedArtifact = "sha256:" + artifact;
            string payloadText = "{\"schema\":\"initiative.local-handoff.v1\",\"scope\":\"LOCAL_SYNTHETIC_HANDOFF_ONLY\","
                + "\"proposal_digest\":\"sha256:" + new string('b', 64)
                + "\",\"proposal\":{\"schema\":\"initiative.proposal.v1\","
                + "\"proposal_id\":\"" + typedArtifact + "\","
                + "\"idempotency_key\":\"" + typedArtifact + "\","
                + "\"event_id\":\"test.event\",\"generation\":\"" + generation + "\","
                + "\"goal_digest\":\"sha256:" + new string('c', 64) + "\","
                + "\"created_at\":100,\"expires_at\":200,\"ttl_seconds\":100,"
                + "\"target_class\":\"SYNTHETIC_LOCAL_ONLY\",\"message\":\"fixture\","
                + "\"reason\":\"bounded test\",\"salience\":{},"
                + "\"execution_authorized\":false,\"contact_authorized\":false,"
                + "\"delivery_verified\":false,\"provider_evidence\":\"INJECTED_PROVIDER_UNVERIFIED\","
                + "\"evidence_class\":\"INJECTED_PROVIDER_UNVERIFIED\",\"provenance\":{},"
                + "\"origin\":\"OBSESSION_RESIDENT_SYNTHETIC_V1\","
                + "\"category\":\"OWNER_DIRECTED_SYNTHETIC_DIAGNOSTIC\",\"propose_only\":true},"
                + "\"delivery_verified\":false,\"contact_authorized\":false}\n";
            byte[] payload = Encoding.UTF8.GetBytes(payloadText);
            string digest = Sha256Hex(payload);
            string envelope = "PUBLISH|" + generation + "|" + artifact + "|"
                + Convert.ToBase64String(payload) + "|V1";
            string grant = "GRANT|" + generation + "|" + artifact + "|" + digest
                + "|" + DateTime.UtcNow.AddMinutes(2).Ticks + "|V1";
            string grantResult = initial.OperatorCommand(grant);
            string wrongTypedDigest = payloadText.Replace("\"proposal_digest\":\"sha256:",
                                                         "\"proposal_digest\":\"");
            string malformed = "PUBLISH|" + generation + "|" + artifact + "|"
                + Convert.ToBase64String(Encoding.UTF8.GetBytes(wrongTypedDigest)) + "|V1";
            string wrongNestedFlag = payloadText.Replace("\"execution_authorized\":false",
                                                         "\"execution_authorized\":true");
            string unsafeEnvelope = "PUBLISH|" + generation + "|" + artifact + "|"
                + Convert.ToBase64String(Encoding.UTF8.GetBytes(wrongNestedFlag)) + "|V1";
            string duplicateTop = payloadText.Replace(
                "\"delivery_verified\":false,\"contact_authorized\":false}\n",
                "\"delivery_verified\":false,\"contact_authorized\":false,\"contact_authorized\":false}\n");
            string duplicateNested = payloadText.Replace(
                "\"execution_authorized\":false",
                "\"execution_authorized\":false,\"execution_authorized\":false");
            string escapedNestedKey = payloadText.Replace(
                "\"execution_authorized\":false",
                "\"ex\\u0065cution_authorized\":false");
            string deniedRawDigest = initial.PublishCommand(malformed);
            string deniedUnsafeNested = initial.PublishCommand(unsafeEnvelope);
            string deniedDuplicateTop = initial.PublishCommand("PUBLISH|" + generation + "|" + artifact
                + "|" + Convert.ToBase64String(Encoding.UTF8.GetBytes(duplicateTop)) + "|V1");
            string deniedDuplicateNested = initial.PublishCommand("PUBLISH|" + generation + "|" + artifact
                + "|" + Convert.ToBase64String(Encoding.UTF8.GetBytes(duplicateNested)) + "|V1");
            string deniedEscapedNestedKey = initial.PublishCommand("PUBLISH|" + generation + "|" + artifact
                + "|" + Convert.ToBase64String(Encoding.UTF8.GetBytes(escapedNestedKey)) + "|V1");
            // Diagnostic of the actual .NET framework parser behavior: the
            // security result does not depend on whether it collapses or
            // throws on duplicate names, because the scanner runs first.
            string frameworkDuplicateBehavior;
            try
            {
                Dictionary<string, object> parsed = new JavaScriptSerializer()
                    .DeserializeObject("{\"flag\":false,\"flag\":true}")
                    as Dictionary<string, object>;
                frameworkDuplicateBehavior = parsed != null && parsed.Count == 1
                    ? "COLLAPSED_TO_" + parsed["flag"] : "OTHER";
            }
            catch (Exception) { frameworkDuplicateBehavior = "THREW"; }
            string first = initial.PublishCommand(envelope);
            string stopped = initial.OperatorCommand("STOP|" + generation + "|V1");
            string afterStop = initial.PublishCommand(envelope);
            StopCustodian restarted = new StopCustodian();
            restarted.LoadState();
            string afterRestart = restarted.PublishCommand(envelope);
            // These selftests use per-PID stage-only pipe names, never the
            // production pipe names. The second first-instance bind must fail.
            bool collisionDenied = false;
            bool reacquireAfterRelease = false;
            string collisionDiagnostic = "UNATTEMPTED";
            using (NamedPipeServerStream reserved = restarted.CreateExclusivePipe(false))
            {
                try
                {
                    using (NamedPipeServerStream unexpected = restarted.CreateExclusivePipe(false))
                        collisionDiagnostic = "SECOND_BIND_SUCCEEDED";
                }
                catch (Win32Exception ex)
                {
                    collisionDiagnostic = "WIN32_" + ex.NativeErrorCode;
                    // ERROR_ACCESS_DENIED (5): first-instance collision.
                    // ERROR_PIPE_BUSY (231): the single permitted instance
                    // is already reserved. Both reject a second server.
                    collisionDenied = ex.NativeErrorCode == 5 || ex.NativeErrorCode == 231;
                }
                catch (Exception ex)
                {
                    collisionDiagnostic = "OTHER_" + ex.GetType().FullName + "_" + ex.Message;
                }
            }
            using (NamedPipeServerStream reacquired = restarted.CreateExclusivePipe(false))
                reacquireAfterRelease = reacquired != null;
            restarted.OnStop();
            bool stopQuiesced = !restarted.healthy && !restarted.running;
            Console.WriteLine("TEST_ONLY grant=" + grantResult + " first=" + first
                + " stopped=" + stopped + " afterStop=" + afterStop
                + " afterRestart=" + afterRestart
                + " collisionDenied=" + collisionDenied
                + " collisionDiagnostic=" + collisionDiagnostic
                + " reacquireAfterRelease=" + reacquireAfterRelease
                + " stopQuiesced=" + stopQuiesced
                + " rawDigest=" + deniedRawDigest + " unsafeNested=" + deniedUnsafeNested
                + " dupTop=" + deniedDuplicateTop + " dupNested=" + deniedDuplicateNested
                + " escapedKey=" + deniedEscapedNestedKey
                + " frameworkDuplicate=" + frameworkDuplicateBehavior);
            if (!grantResult.StartsWith("GRANTED|") || !first.StartsWith("PUBLISHED|")
                || !stopped.StartsWith("STOPPED|")
                || afterStop != "HOLD|STOP_ACTIVE_OR_UNVERIFIED"
                || afterRestart != "HOLD|STOP_ACTIVE_OR_UNVERIFIED"
                || deniedRawDigest != "HOLD|NOT_SYNTHETIC_HANDOFF"
                || deniedUnsafeNested != "HOLD|NOT_SYNTHETIC_HANDOFF"
                || deniedDuplicateTop != "HOLD|NOT_SYNTHETIC_HANDOFF"
                || deniedDuplicateNested != "HOLD|NOT_SYNTHETIC_HANDOFF"
                || deniedEscapedNestedKey != "HOLD|NOT_SYNTHETIC_HANDOFF"
                || !collisionDenied || !reacquireAfterRelease || !stopQuiesced)
                Environment.ExitCode = 1;
#if STAGING_PIPE_TEST
            string[] stageArgs = Environment.GetCommandLineArgs();
            if (stageArgs.Length == 2 && stageArgs[1] == "--collision")
                StageCollisionProbe();
            else if (stageArgs.Length == 2 && stageArgs[1] == "--idle-stop-stress")
                StageIdleStopStress();
            else if (stageArgs.Length == 2 && stageArgs[1] == "--identity-window")
                StageIdentityWindow();
            else if (stageArgs.Length == 1)
                StagePipeExercise(payloadText, generation, typedArtifact);
            else
            {
                Console.Error.WriteLine("USAGE: Wave12.Stage.exe"
                    + " [--collision|--identity-window|--idle-stop-stress]");
                Environment.ExitCode = 64;
            }
#endif
#else
            ServiceBase.Run(new StopCustodian());
#endif
        }
    }
}
