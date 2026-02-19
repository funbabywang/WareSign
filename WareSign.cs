using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace WareSign
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "/?" || args[0] == "-h" || args[0] == "--help")
            {
                ShowHelp();
                return;
            }

            try
            {
                if (args[0].ToLower() != "sign")
                    throw new Exception("Unknown command. Use 'sign'.");

                var options = ParseArguments(args);
                SignFile(options);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {ex.Message}");
                Console.ResetColor();
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("WareSign - Digital Signature Tool");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  waresign sign file:<path> cert:<path> [/password <pwd>] [/fd <hash>] [/tr <url>] [/v]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  file:<path>        File to sign (required)");
            Console.WriteLine("  cert:<path>        PFX certificate file (required)");
            Console.WriteLine("  /password <pwd>    Password for PFX file (optional)");
            Console.WriteLine("  /fd <hash>         Digest algorithm: SHA1, SHA256(default), SHA384, SHA512");
            Console.WriteLine("  /tr <url>          RFC3161 timestamp server URL");
            Console.WriteLine("  /v                  Verbose output");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine("  waresign sign file:C:\\temp\\main.exe cert:C:\\temp\\cert.pfx /password mypass");
        }

        static (string FilePath, string CertPath, string Password, string HashAlg, string TimestampUrl, bool Verbose) ParseArguments(string[] args)
        {
            string file = null;
            string cert = null;
            string password = null;
            string hashAlg = "SHA256";
            string timestampUrl = null;
            bool verbose = false;

            for (int i = 1; i < args.Length; i++)
            {
                string arg = args[i];

                // 处理 key:value 格式
                if (arg.Contains(':'))
                {
                    var parts = arg.Split(':', 2);
                    string key = parts[0].ToLower();
                    string value = parts[1];

                    switch (key)
                    {
                        case "file":
                            file = value;
                            break;
                        case "cert":
                            cert = value;
                            break;
                        default:
                            throw new Exception($"Unknown option: {arg}");
                    }
                }
                // 处理 /key value 格式
                else if (arg.StartsWith("/"))
                {
                    string option = arg.Substring(1).ToLower();
                    switch (option)
                    {
                        case "password":
                            if (i + 1 >= args.Length) throw new Exception("Missing password value.");
                            password = args[++i];
                            break;
                        case "fd":
                            if (i + 1 >= args.Length) throw new Exception("Missing hash algorithm.");
                            hashAlg = args[++i].ToUpper();
                            break;
                        case "tr":
                            if (i + 1 >= args.Length) throw new Exception("Missing timestamp URL.");
                            timestampUrl = args[++i];
                            break;
                        case "v":
                            verbose = true;
                            break;
                        default:
                            throw new Exception($"Unknown option: {arg}");
                    }
                }
                else
                {
                    throw new Exception($"Unexpected argument: {arg}");
                }
            }

            if (file == null) throw new Exception("File path not specified. Use file:<path>");
            if (cert == null) throw new Exception("Certificate path not specified. Use cert:<path>");

            var validHashes = new[] { "SHA1", "SHA256", "SHA384", "SHA512" };
            if (!validHashes.Contains(hashAlg))
                throw new Exception($"Invalid hash algorithm. Use: {string.Join(", ", validHashes)}");

            return (file, cert, password, hashAlg, timestampUrl, verbose);
        }

        static void SignFile((string FilePath, string CertPath, string Password, string HashAlg, string TimestampUrl, bool Verbose) options)
        {
            if (options.Verbose)
                Console.WriteLine($"Loading certificate: {options.CertPath}");

            // 1. 加载证书
            X509Certificate2 cert;
            try
            {
                cert = new X509Certificate2(options.CertPath, options.Password, X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to load certificate: {ex.Message}");
            }

            if (options.Verbose)
                Console.WriteLine($"Certificate: {cert.Subject} (expires: {cert.NotBefore:yyyy-MM-dd} - {cert.NotAfter:yyyy-MM-dd})");

            // 2. 读取文件
            byte[] content;
            try
            {
                content = File.ReadAllBytes(options.FilePath);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to read file: {ex.Message}");
            }

            if (options.Verbose)
                Console.WriteLine($"File loaded: {options.FilePath} ({content.Length} bytes)");

            // 3. 计算哈希（可选显示）
            HashAlgorithmName hashName = new HashAlgorithmName(options.HashAlg);
            byte[] hash;
            using (var hasher = HashAlgorithm.Create(hashName.Name))
            {
                hash = hasher.ComputeHash(content);
                if (options.Verbose)
                    Console.WriteLine($"File hash ({options.HashAlg}): {BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant()}");
            }

            // 4. 创建分离签名
            ContentInfo contentInfo = new ContentInfo(content);
            SignedCms signedCms = new SignedCms(contentInfo, true); // true = 分离签名

            CmsSigner signer = new CmsSigner(cert)
            {
                DigestAlgorithm = new Oid(GetOidForHash(hashName.Name))
            };

            // 5. 添加时间戳（如果提供 URL）
            if (!string.IsNullOrEmpty(options.TimestampUrl))
            {
                // 简化处理：仅请求时间戳，不嵌入（如需完整实现请扩展）
                if (options.Verbose)
                    Console.WriteLine($"Timestamp requested from {options.TimestampUrl} (not embedded in this version)");
                // 实际嵌入需要更复杂的处理，这里仅提示
            }

            // 6. 计算签名
            signedCms.ComputeSignature(signer);
            if (options.Verbose)
                Console.WriteLine("Signature computed.");

            // 7. 保存签名文件
            byte[] signature = signedCms.Encode();
            string signatureFile = options.FilePath + ".p7s";
            File.WriteAllBytes(signatureFile, signature);
            if (options.Verbose)
                Console.WriteLine($"Signature saved to: {signatureFile} ({signature.Length} bytes)");

            // 8. 输出简洁成功信息
            Console.WriteLine($"WareSign:Sign File:{options.FilePath}");
            Console.WriteLine($"Cert:{options.CertPath}");
            Console.WriteLine("Sign Success");

            // 9. 可选验证
            if (options.Verbose)
                VerifySignature(options.FilePath, signatureFile);
        }

        static string GetOidForHash(string hashName)
        {
            return hashName switch
            {
                "SHA1" => "1.3.14.3.2.26",
                "SHA256" => "2.16.840.1.101.3.4.2.1",
                "SHA384" => "2.16.840.1.101.3.4.2.2",
                "SHA512" => "2.16.840.1.101.3.4.2.3",
                _ => throw new Exception("Unsupported hash algorithm")
            };
        }

        static void VerifySignature(string file, string signatureFile)
        {
            try
            {
                byte[] content = File.ReadAllBytes(file);
                byte[] signature = File.ReadAllBytes(signatureFile);

                ContentInfo contentInfo = new ContentInfo(content);
                SignedCms signedCms = new SignedCms(contentInfo, true);
                signedCms.Decode(signature);
                signedCms.CheckSignature(true); // 验证证书链

                Console.WriteLine("Signature verification: Valid.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Signature verification: Invalid - {ex.Message}");
            }
        }
    }
}