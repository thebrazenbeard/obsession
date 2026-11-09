// SOURCE-ONLY EXPERIMENT. Staging compile and isolated semantic test only;
// no production SCM registration, host authority, or runtime installation.
// .NET Framework 4.x, Windows Service, no third-party dependencies.
// Protected host output is LOCAL_SYNTHETIC_HANDOFF_ONLY, never a recipient send.
using System;
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
        private const string OperatorPipe = "VeraObsessionStopOperatorV1";
        private const string PublishPipe = "VeraObsessionStopPublishV1";
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
                using (WaitHandle completed = pending.AsyncWaitHandle)
                {
                    if (!completed.WaitOne(timeout))
                        throw new IOException("whole-frame pipe deadline");
                    got = s.EndRead(pending);
                }
                if (got <= 0) throw new EndOfStreamException();
                offset += got;
                count -= got;
            }
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

        private static void WriteWithDeadline(Stream stream, byte[] buffer,
                                              long deadline)
        {
            int timeout = RemainingMilliseconds(deadline);
            IAsyncResult pending = stream.BeginWrite(buffer, 0, buffer.Length, null, null);
            using (WaitHandle completed = pending.AsyncWaitHandle)
            {
                if (!completed.WaitOne(timeout)) throw new IOException("whole-frame pipe deadline");
                stream.EndWrite(pending);
            }
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
            if (!operatorAccess)
                acl.AddAccessRule(new PipeAccessRule(residentSid, PipeAccessRights.ReadWrite,
                                                     AccessControlType.Allow));
            return acl;
        }

        private void ServePipe(bool operatorAccess)
        {
            while (running)
            {
                try
                {
                    using (NamedPipeServerStream pipe = new NamedPipeServerStream(
                        operatorAccess ? OperatorPipe : PublishPipe,
                        PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous, 0, 0, PipeAcl(operatorAccess)))
                    {
                        IAsyncResult pending = pipe.BeginWaitForConnection(null, null);
                        while (running && !pending.AsyncWaitHandle.WaitOne(250)) { }
                        if (!running) break;
                        pipe.EndWaitForConnection(pending);
                        string answer;
                        try
                        {
                            string request = DecodeUtf8(ReadFrame(pipe));
                            answer = operatorAccess ? OperatorCommand(request) : PublishCommand(request);
                        }
                        catch (Exception) { answer = "HOLD|MALFORMED_OR_FAILED"; }
                        WriteFrame(pipe, answer);
                    }
                }
                catch (Exception)
                {
                    // No provider-driven bypass to publication. Failed requests
                    // remain denied; the service must be monitored externally.
                    Thread.Sleep(250);
                }
            }
        }

        protected override void OnStart(string[] args)
        {
            LoadState(); // fail before pipes expose any publication capability
            running = true;
            operatorThread = new Thread(() => ServePipe(true));
            publishThread = new Thread(() => ServePipe(false));
            operatorThread.IsBackground = true;
            publishThread.IsBackground = true;
            operatorThread.Start();
            publishThread.Start();
        }

        protected override void OnStop()
        {
            running = false;
        }

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
            Console.WriteLine("TEST_ONLY grant=" + grantResult + " first=" + first
                + " stopped=" + stopped + " afterStop=" + afterStop
                + " afterRestart=" + afterRestart
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
                || deniedEscapedNestedKey != "HOLD|NOT_SYNTHETIC_HANDOFF")
                Environment.ExitCode = 1;
#else
            ServiceBase.Run(new StopCustodian());
#endif
        }
    }
}
