using System.Text;
using System.Security.Cryptography;
using Sodium;
using System.Text.RegularExpressions;
using HtmlAgilityPack;
using LoginFB;
using System.Net;
using OtpNet;
using Newtonsoft.Json.Linq;
using NewtonsoftJsonException = Newtonsoft.Json.JsonException;
using SystemTextJsonException = System.Text.Json.JsonException;
namespace LoginFB
{

    public class PasswordEncryption
    {
        private const int PUBLIC_KEY_LENGTH = 64;
        private const int I = 1;
        private const int J = 1;
        private const int K = 1;
        private const int L = 48;
        private const int M = 2;
        private const int N = 32;
        private const int O = 16;
        private static readonly int P = J + K + M + N + L + O;

        public class PublicKeyData
        {
            public string PublicKey { get; set; }
            public int KeyId { get; set; }
        }

        private static byte[] Seal(byte[] buffer, byte[] publicKey)
        {
            return SealedPublicKeyBox.Create(buffer, publicKey);
        }

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                            .ToArray();
        }
        public static byte[] HashPassword(int keyId, string publicKeyHex, byte[] password, byte[] time)
        {
            if (publicKeyHex.Length != PUBLIC_KEY_LENGTH)
                throw new ArgumentException("public key is not a valid hex string");

            byte[] publicKey = StringToByteArray(publicKeyHex);
            if (publicKey == null || publicKey.Length == 0)
                throw new ArgumentException("public key is not a valid hex string");

            int totalLength = P + password.Length;
            byte[] result = new byte[totalLength];
            int offset = 0;

            result[offset] = I;
            offset += J;

       
            result[offset] = (byte)keyId;
            offset += K;

    
            byte[] key = new byte[N];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];

            byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
            byte[] ciphertext = new byte[password.Length];

            using (var aesGcm = new AesGcm(key))
            {
                aesGcm.Encrypt(nonce, password, ciphertext, tag, time);
            }

 
            byte[] sealedKey = Seal(key, publicKey);


            result[offset] = (byte)(sealedKey.Length & 0xFF);
            result[offset + 1] = (byte)((sealedKey.Length >> 8) & 0xFF);
            offset += M;


            Buffer.BlockCopy(sealedKey, 0, result, offset, sealedKey.Length);
            offset += N + L;

            if (sealedKey.Length != N + L)
                throw new Exception("encrypted key is the wrong length");

            byte[] encryptedData = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, encryptedData, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, encryptedData, ciphertext.Length, tag.Length);

            byte[] tagPart = encryptedData.Skip(encryptedData.Length - O).Take(O).ToArray();
            byte[] encryptedDataWithoutTag = encryptedData.Take(encryptedData.Length - O).ToArray();

            Buffer.BlockCopy(tagPart, 0, result, offset, O);
            offset += O;
            Buffer.BlockCopy(encryptedDataWithoutTag, 0, result, offset, encryptedDataWithoutTag.Length);

            return result;
        }
        public static string HashManager(PublicKeyData publicKeyData, string timestamp, string password)
        {
            try
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] timeBytes = Encoding.UTF8.GetBytes(timestamp);

                byte[] hashedBytes = HashPassword(publicKeyData.KeyId, publicKeyData.PublicKey, passwordBytes, timeBytes);
                return Convert.ToBase64String(hashedBytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in HashManager: {ex.Message}");
                throw;
            }
        }

        public static PublicKeyData ExtractPublicKeyData(string htmlContent)
        {
            try
            {
                var publicKeyPattern = "\"publicKey\":\"([a-zA-Z0-9]+)\"";
                var keyIdPattern = "\"keyId\":(\\d+)";

                var publicKeyMatch = Regex.Match(htmlContent, publicKeyPattern);
                var keyIdMatch = Regex.Match(htmlContent, keyIdPattern);

                if (publicKeyMatch.Success && keyIdMatch.Success)
                {
                    return new PublicKeyData
                    {
                        PublicKey = publicKeyMatch.Groups[1].Value,
                        KeyId = int.Parse(keyIdMatch.Groups[1].Value)
                    };
                }

                throw new Exception("Không tìm thấy public key hoặc key ID.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error extracting public key data: {ex.Message}");
                throw;
            }
        }

        public static string HashPasswordMain(string password, string htmlContent)
        {
            try
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                var publicKeyData = ExtractPublicKeyData(htmlContent);

                Console.WriteLine($"Found Public Key: {publicKeyData.PublicKey}");
                Console.WriteLine($"Found Key ID: {publicKeyData.KeyId}");

                var hashedPassword = HashManager(publicKeyData, timestamp, password);
                return $"#PWD_BROWSER:5:{timestamp}:{hashedPassword}";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error hashing password: {ex.Message}");
                throw;
            }
        }
    }
}
public class FacebookLogin
{
    private readonly HttpClient _client;

   
    public static string GetString(string input, string start, string end)
    {
        input = " " + input;
        int startIndex = input.IndexOf(start);
        if (startIndex == -1) return string.Empty;
        startIndex += start.Length;

        int endIndex = input.IndexOf(end, startIndex);
        if (endIndex == -1) return string.Empty;

        return input.Substring(startIndex, endIndex - startIndex);
    }
    public async Task LoginAsync(string email, string password, string String2FA)
    {
        try
        {

            var handler = new HttpClientHandler
            {
                UseCookies = true,
                CookieContainer = new CookieContainer()


            };
             var client = new HttpClient(handler);

                // Tạo request với header riêng
                var request1 = new HttpRequestMessage(HttpMethod.Get, "https://www.facebook.com");

                // Đặt header riêng cho request1
                request1.Headers.Add("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
                request1.Headers.Add("accept-language", "vi-VN,vi;q=0.9");
                request1.Headers.Add("cache-control", "max-age=0");
                request1.Headers.Add("priority", "u=0, i");
                request1.Headers.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"");
                request1.Headers.Add("sec-ch-ua-mobile", "?0");
                request1.Headers.Add("sec-ch-ua-platform", "\"Windows\"");
                request1.Headers.Add("sec-fetch-dest", "document");
                request1.Headers.Add("sec-fetch-mode", "navigate");
                request1.Headers.Add("sec-fetch-site", "none");
                request1.Headers.Add("sec-fetch-user", "?1");
                request1.Headers.Add("upgrade-insecure-requests", "1");
                request1.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");

                // Gửi request1
                HttpResponseMessage response1 = await client.SendAsync(request1);
                response1.EnsureSuccessStatusCode();

                // Đọc nội dung response
                byte[] contentBytes = await response1.Content.ReadAsByteArrayAsync();
                string contents = Encoding.UTF8.GetString(contentBytes);

                // Load HTML vào HtmlAgilityPack
                var doc = new HtmlDocument();
                doc.LoadHtml(contents);

                //Console.WriteLine(contents);

                string encryptedPassword = PasswordEncryption.HashPasswordMain(password, contents);

            
            var request = new HttpRequestMessage(HttpMethod.Post, "https://graph.facebook.com/graphql");

            // Chuỗi JSON gốc với placeholder cho email và password
            string jsonTemplate = "{\"params\":{\"params\":\"{\\\"params\\\":\\\"{\\\\\\\"client_input_params\\\\\\\":{\\\\\\\"sim_phones\\\\\\\":[],\\\\\\\"secure_family_device_id\\\\\\\":\\\\\\\"d156d4ac-c5a7-4d6d-8aad-e529aeaae8f1\\\\\\\",\\\\\\\"has_granted_read_contacts_permissions\\\\\\\":0,\\\\\\\"auth_secure_device_id\\\\\\\":\\\\\\\"\\\\\\\",\\\\\\\"has_whatsapp_installed\\\\\\\":0,\\\\\\\"password\\\\\\\":\\\\\\\""+ encryptedPassword + "\\\\\\\",\\\\\\\"sso_token_map_json_string\\\\\\\":\\\\\\\"{\\\\\\\\\\\\\\\""+email+"\\\\\\\\\\\\\\\":[{\\\\\\\\\\\\\\\"credential_type\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"nonce\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"token\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"ikIcfYBA\\\\\\\\\\\\\\\"}]}\\\\\\\",\\\\\\\"event_flow\\\\\\\":\\\\\\\"login_manual\\\\\\\",\\\\\\\"password_contains_non_ascii\\\\\\\":\\\\\\\"false\\\\\\\",\\\\\\\"sim_serials\\\\\\\":[],\\\\\\\"client_known_key_hash\\\\\\\":\\\\\\\"\\\\\\\",\\\\\\\"encrypted_msisdn\\\\\\\":\\\\\\\"\\\\\\\",\\\\\\\"has_granted_read_phone_permissions\\\\\\\":0,\\\\\\\"app_manager_id\\\\\\\":\\\\\\\"\\\\\\\",\\\\\\\"should_show_nested_nta_from_aymh\\\\\\\":1,\\\\\\\"device_id\\\\\\\":\\\\\\\"af7e0f80-ab9c-83dd-3603-046b2dffddc8\\\\\\\",\\\\\\\"login_attempt_count\\\\\\\":1,\\\\\\\"machine_id\\\\\\\":\\\\\\\"yr-ZZ0tOXaplIq-yh3QKgcVY\\\\\\\",\\\\\\\"accounts_list\\\\\\\":[{\\\\\\\"uid\\\\\\\":\\\\\\\""+email+"\\\\\\\",\\\\\\\"credential_type\\\\\\\":\\\\\\\"nonce\\\\\\\",\\\\\\\"account_type\\\\\\\":\\\\\\\"\\\\\\\",\\\\\\\"metadata\\\\\\\":{\\\\\\\"last_access_time\\\\\\\":\\\\\\\"1738129380679\\\\\\\"},\\\\\\\"token\\\\\\\":\\\\\\\"ikIcfYBA\\\\\\\"}],\\\\\\\"family_device_id\\\\\\\":\\\\\\\"af7e0f80-ab9c-83dd-3603-046b2dffddc8\\\\\\\",\\\\\\\"fb_ig_device_id\\\\\\\":[],\\\\\\\"device_emails\\\\\\\":[],\\\\\\\"try_num\\\\\\\":1,\\\\\\\"lois_settings\\\\\\\":{\\\\\\\"lois_token\\\\\\\":\\\\\\\"\\\\\\\"},\\\\\\\"event_step\\\\\\\":\\\\\\\"home_page\\\\\\\",\\\\\\\"headers_infra_flow_id\\\\\\\":\\\\\\\"\\\\\\\",\\\\\\\"openid_tokens\\\\\\\":{},\\\\\\\"contact_point\\\\\\\":\\\\\\\""+email+"\\\\\\\"},\\\\\\\"server_params\\\\\\\":{\\\\\\\"should_trigger_override_login_2fa_action\\\\\\\":0,\\\\\\\"is_from_logged_out\\\\\\\":0,\\\\\\\"should_trigger_override_login_success_action\\\\\\\":0,\\\\\\\"login_credential_type\\\\\\\":\\\\\\\"none\\\\\\\",\\\\\\\"server_login_source\\\\\\\":\\\\\\\"login\\\\\\\",\\\\\\\"waterfall_id\\\\\\\":\\\\\\\"9bd15e6d-e129-4925-8035-bb1dce82b0ab\\\\\\\",\\\\\\\"login_source\\\\\\\":\\\\\\\"Login\\\\\\\",\\\\\\\"is_platform_login\\\\\\\":0,\\\\\\\"pw_encryption_try_count\\\\\\\":1,\\\\\\\"INTERNAL__latency_qpl_marker_id\\\\\\\":36707139,\\\\\\\"offline_experiment_group\\\\\\\":\\\\\\\"caa_iteration_v6_perf_fb_2\\\\\\\",\\\\\\\"is_from_landing_page\\\\\\\":0,\\\\\\\"password_text_input_id\\\\\\\":\\\\\\\"n0da4y:69\\\\\\\",\\\\\\\"is_from_empty_password\\\\\\\":0,\\\\\\\"is_from_msplit_fallback\\\\\\\":0,\\\\\\\"ar_event_source\\\\\\\":\\\\\\\"login_home_page\\\\\\\",\\\\\\\"username_text_input_id\\\\\\\":\\\\\\\"n0da4y:68\\\\\\\",\\\\\\\"layered_homepage_experiment_group\\\\\\\":null,\\\\\\\"device_id\\\\\\\":\\\\\\\"af7e0f80-ab9c-83dd-3603-046b2dffddc8\\\\\\\",\\\\\\\"INTERNAL__latency_qpl_instance_id\\\\\\\":1.39134171400171E14,\\\\\\\"reg_flow_source\\\\\\\":\\\\\\\"aymh_single_profile_native_integration_point\\\\\\\",\\\\\\\"is_caa_perf_enabled\\\\\\\":1,\\\\\\\"credential_type\\\\\\\":\\\\\\\"password\\\\\\\",\\\\\\\"is_from_password_entry_page\\\\\\\":0,\\\\\\\"caller\\\\\\\":\\\\\\\"gslr\\\\\\\",\\\\\\\"family_device_id\\\\\\\":\\\\\\\"af7e0f80-ab9c-83dd-3603-046b2dffddc8\\\\\\\",\\\\\\\"is_from_assistive_id\\\\\\\":0,\\\\\\\"access_flow_version\\\\\\\":\\\\\\\"F2_FLOW\\\\\\\",\\\\\\\"is_from_logged_in_switcher\\\\\\\":0}}\\\"}\",\"bloks_versioning_id\":\"c3cc18230235472b54176a5922f9b91d291342c3a276e2644dbdb9760b96deec\",\"app_id\":\"com.bloks.www.bloks.caa.login.async.send_login_request\"},\"scale\":\"3\",\"nt_context\":{\"styles_id\":\"e6c6f61b7a86cdf3fa2eaaffa982fbd1\",\"using_white_navbar\":true,\"pixel_ratio\":3,\"is_push_on\":true,\"bloks_version\":\"c3cc18230235472b54176a5922f9b91d291342c3a276e2644dbdb9760b96deec\"}}";


            request.Headers.TryAddWithoutValidation("User-Agent", "[FBAN/FB4A;FBAV/417.0.0.33.65;FBBV/480086274;FBDM/{density=3.0,width=1080,height=1920};FBLC/vi_VN;FBRV/0;FBCR/MobiFone;FBMF/samsung;FBBD/samsung;FBPN/com.facebook.katana;FBDV/SM-B7285;FBSV/9;FBOP/1;FBCA/x86:armeabi-v7a;]");
            request.Headers.Add("x-fb-request-analytics-tags", "{\"network_tags\":{\"product\":\"350685531728\",\"purpose\":\"fetch\",\"request_category\":\"graphql\",\"retry_attempt\":\"0\"},\"application_tags\":\"graphservice\"}");
            //request.Headers.Add("x-fb-ta-logging-ids", "graphql:cb3149ec-76b6-457c-833a-769a88d044b3");
            request.Headers.Add("x-fb-device-group", "1075");
            //request.Headers.Add("x-fb-session-id", "nid=3vK6rI4oPTpX;tid=250;nc=0;fc=0;bc=0;cid=ca1302322f01e7e3fef1c9e3c01d20c3");
            request.Headers.Add("x-fb-privacy-context", "3643298472347298");
            request.Headers.Add("x-graphql-client-library", "graphservice");
            request.Headers.Add("x-fb-qpl-active-flows-json", "{\"schema_version\":\"v2\",\"inprogress_qpls\":[{\"marker_id\":25952257,\"annotations\":{\"current_endpoint\":\"bloks_unknown_class:bloks_unknown\"}}],\"snapshot_attributes\":{}}");
            request.Headers.Add("x-fb-friendly-name", "FbBloksActionRootQuery-com.bloks.www.bloks.caa.login.async.send_login_request");
            request.Headers.Add("x-fb-background-state", "1");
            request.Headers.Add("x-fb-connection-type", "WIFI");
            request.Headers.Add("x-graphql-request-purpose", "fetch");
            request.Headers.Add("authorization", "OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32");
            request.Headers.Add("x-fb-net-hni", "45201");
            request.Headers.Add("x-fb-sim-hni", "45201");
            request.Headers.Add("x-tigon-is-retry", "False");
            request.Headers.Add("priority", "u=0");
            request.Headers.Add("x-fb-http-engine", "Liger");
            request.Headers.Add("x-fb-client-ip", "True");
            request.Headers.Add("x-fb-server-cluster", "True");
            request.Headers.Add("x-fb-connection-token", "ca1302322f01e7e3fef1c9e3c01d20c3");
            var collection = new List<KeyValuePair<string, string>>();
            collection.Add(new("method", "post"));
            collection.Add(new("pretty", "false"));
            collection.Add(new("format", "json"));
            collection.Add(new("server_timestamps", "true"));
            collection.Add(new("locale", "vi_VN"));
            collection.Add(new("purpose", "fetch"));
            collection.Add(new("fb_api_req_friendly_name", "FbBloksActionRootQuery-com.bloks.www.bloks.caa.login.async.send_login_request"));
            collection.Add(new("fb_api_caller_class", "graphservice"));
            collection.Add(new("client_doc_id", "11994080423068421059028841356"));
            collection.Add(new("variables", jsonTemplate));
            collection.Add(new("fb_api_analytics_tags", "[\"GraphServices\"]"));
            collection.Add(new("client_trace_id", "cb3149ec-76b6-457c-833a-769a88d044b3"));
            var content = new FormUrlEncodedContent(collection);
            request.Content = content;

            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            //Console.WriteLine(await response.Content.ReadAsStringAsync());
            response.EnsureSuccessStatusCode();
            string responseBody = await response.Content.ReadAsStringAsync();


            string responseBodyUnescape = Regex.Unescape(Regex.Unescape(Regex.Unescape(Regex.Unescape(responseBody))));



            if (responseBody.Contains("two_fac_redirect"))  // 2FA
            {
                Console.WriteLine("2FA ");
                //foreach (var header in response.Headers)
                //{
                //    Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
                //}
                try
                {
                    string UnescapeBody = Regex.Unescape(Regex.Unescape(Regex.Unescape(responseBody)));

                    //Console.WriteLine(UnescapeBody);

                    string two_step_verification_context = FacebookLogin.GetString(UnescapeBody, "\"machine_id\", \"device_id\", \"family_device_id\", \"INTERNAL_INFRA_screen_id\"), (bk.action.array.Make, \"", "\"");

                    Console.WriteLine("Giá trị Two2FA " + two_step_verification_context);

                    string otpCode = new Totp(Base32Encoding.ToBytes(String2FA)).ComputeTotp();

                    Console.WriteLine("Giá trị OTP " + otpCode);

                    string variablesCode = "{\"params\":{\"params\":\"{\\\"params\\\":\\\"{\\\\\\\"client_input_params\\\\\\\":{\\\\\\\"auth_secure_device_id\\\\\\\":\\\\\\\"\\\\\\\",\\\\\\\"machine_id\\\\\\\":\\\\\\\"yr-ZZ0tOXaplIq-yh3QKgcVY\\\\\\\",\\\\\\\"code\\\\\\\":\\\\\\\"" + otpCode + "\\\\\\\",\\\\\\\"should_trust_device\\\\\\\":1,\\\\\\\"family_device_id\\\\\\\":\\\\\\\"af7e0f80-ab9c-83dd-3603-046b2dffddc8\\\\\\\",\\\\\\\"device_id\\\\\\\":\\\\\\\"af7e0f80-ab9c-83dd-3603-046b2dffddc8\\\\\\\"},\\\\\\\"server_params\\\\\\\":{\\\\\\\"INTERNAL__latency_qpl_marker_id\\\\\\\":36707139,\\\\\\\"device_id\\\\\\\":\\\\\\\"af7e0f80-ab9c-83dd-3603-046b2dffddc8\\\\\\\",\\\\\\\"challenge\\\\\\\":\\\\\\\"totp\\\\\\\",\\\\\\\"machine_id\\\\\\\":\\\\\\\"yr-ZZ0tOXaplIq-yh3QKgcVY\\\\\\\",\\\\\\\"INTERNAL__latency_qpl_instance_id\\\\\\\":1.72785847600065E14,\\\\\\\"two_step_verification_context\\\\\\\":\\\\\\\"" + two_step_verification_context + "\\\\\\\",\\\\\\\"flow_source\\\\\\\":\\\\\\\"two_factor_login\\\\\\\"}}\\\"}\",\"bloks_versioning_id\":\"c3cc18230235472b54176a5922f9b91d291342c3a276e2644dbdb9760b96deec\",\"app_id\":\"com.bloks.www.two_step_verification.verify_code.async\"},\"scale\":\"3\",\"nt_context\":{\"styles_id\":\"e6c6f61b7a86cdf3fa2eaaffa982fbd1\",\"using_white_navbar\":true,\"pixel_ratio\":3,\"is_push_on\":true,\"bloks_version\":\"c3cc18230235472b54176a5922f9b91d291342c3a276e2644dbdb9760b96deec\"}}";



                    var request3 = new HttpRequestMessage(HttpMethod.Post, "https://graph.facebook.com/graphql");

                    request3.Headers.TryAddWithoutValidation("User-Agent", "[FBAN/FB4A;FBAV/417.0.0.33.65;FBBV/480086274;FBDM/{density=3.0,width=1080,height=1920};FBLC/vi_VN;FBRV/0;FBCR/MobiFone;FBMF/samsung;FBBD/samsung;FBPN/com.facebook.katana;FBDV/SM-B7285;FBSV/9;FBOP/1;FBCA/x86:armeabi-v7a;]");

                    request3.Headers.Add("x-fb-request-analytics-tags", "{\"network_tags\":{\"product\":\"350685531728\",\"purpose\":\"fetch\",\"request_category\":\"graphql\",\"retry_attempt\":\"0\"},\"application_tags\":\"graphservice\"}");
                    request3.Headers.Add("x-fb-ta-logging-ids", "graphql:1edea524-fc08-4eac-9eea-a56214cb7c3a");
                    //request3.Headers.Add("x-fb-device-group", "1075");
                    //request3.Headers.Add("x-fb-session-id", "nid=3vK6rI4oPTpX;tid=2156;nc=0;fc=0;bc=0;cid=ca1302322f01e7e3fef1c9e3c01d20c3");

                    request3.Headers.Add("x-fb-privacy-context", "3643298472347298");
                    request3.Headers.Add("x-graphql-client-library", "graphservice");
                    request3.Headers.Add("x-fb-qpl-active-flows-json", "{\"schema_version\":\"v2\",\"inprogress_qpls\":[{\"marker_id\":25952257,\"annotations\":{\"current_endpoint\":\"bloks_unknown_class:bloks_unknown\"}}],\"snapshot_attributes\":{}}");
                    request3.Headers.Add("x-fb-friendly-name", "FbBloksActionRootQuery-com.bloks.www.two_step_verification.verify_code.async");
                    request3.Headers.Add("x-fb-background-state", "1");
                    request3.Headers.Add("x-fb-connection-type", "WIFI");
                    request3.Headers.Add("x-graphql-request-purpose", "fetch");
                    request3.Headers.Add("authorization", "OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32");
                    request3.Headers.Add("x-fb-net-hni", "45201");
                    request3.Headers.Add("x-fb-sim-hni", "45201");
                    request3.Headers.Add("x-tigon-is-retry", "False");
                    request3.Headers.Add("priority", "u=0");
                    request3.Headers.Add("x-fb-http-engine", "Liger");
                    request3.Headers.Add("x-fb-client-ip", "True");
                    request3.Headers.Add("x-fb-server-cluster", "True");
                    request3.Headers.Add("x-fb-connection-token", "ca1302322f01e7e3fef1c9e3c01d20c3");
                    var collection3 = new List<KeyValuePair<string, string>>();
                    collection3.Add(new("method", "post"));
                    collection3.Add(new("pretty", "false"));
                    collection3.Add(new("format", "json"));
                    collection3.Add(new("server_timestamps", "true"));
                    collection3.Add(new("locale", "vi_VN"));
                    collection3.Add(new("purpose", "fetch"));
                    collection3.Add(new("fb_api_req_friendly_name", "FbBloksActionRootQuery-com.bloks.www.two_step_verification.verify_code.async"));
                    collection3.Add(new("fb_api_caller_class", "graphservice"));
                    collection3.Add(new("client_doc_id", "11994080423068421059028841356"));
                    collection3.Add(new("variables", variablesCode));
                    collection3.Add(new("fb_api_analytics_tags", "[\"GraphServices\"]"));
                    collection3.Add(new("client_trace_id", "1edea524-fc08-4eac-9eea-a56214cb7c3a"));
                    var content3 = new FormUrlEncodedContent(collection3);
                    request3.Content = content3;
                    request3.Content = content3;

                    var response3 = await client.SendAsync(request3);

                    response3.EnsureSuccessStatusCode();
                    var ResultBody = await response3.Content.ReadAsStringAsync();

                    string UnescapeBodyResult = Regex.Unescape(Regex.Unescape(Regex.Unescape(ResultBody)));

                    if (UnescapeBodyResult.Contains("access_token"))  // Nếu đã phê duyệt
                    {
                        //Console.WriteLine(UnescapeBodyResult);
                        try
                        {
                     
                            var accessTokenMatch = Regex.Match(UnescapeBodyResult, @"""access_token"":""(EAAAAUaZA8jlAB[^""]+)""");

                            if (!accessTokenMatch.Success)
                            {
                                throw new Exception("Không tìm thấy access_token");
                            }

                            string accessToken = accessTokenMatch.Groups[1].Value;

            
                            var sessionKeyMatch = Regex.Match(UnescapeBodyResult, @"""session_key"":""([^""]+)""");
                            var uidMatch = Regex.Match(UnescapeBodyResult, @"""uid"":(\d+)");

                            Console.WriteLine("Access Token: " + accessToken);

                            if (sessionKeyMatch.Success)
                            {
                                Console.WriteLine("Session Key: " + sessionKeyMatch.Groups[1].Value);
                            }

                            if (uidMatch.Success)
                            {
                                Console.WriteLine("UID: " + uidMatch.Groups[1].Value);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("Lỗi khi xử lý response: " + ex.Message);
                        }

                        return; 
                    }

                        

                }
                catch (Newtonsoft.Json.JsonException ex) 
                {
                    Console.WriteLine("Lỗi phân tích JSON");
                }

            }

            else if (responseBody.Contains("access_token"))  // LOGIN và get Token thành công
            {
                //Console.WriteLine(responseBodyUnescape);
                try
                {
                    // Sử dụng Regular Expression để tìm access_token và session_cookies
                    var accessTokenMatch = Regex.Match(responseBodyUnescape, @"""access_token"":""([^""]+)""");
                    var sessionCookiesMatch = Regex.Match(responseBodyUnescape, @"""session_cookies"":\[(.*?)\]");

                    if (!accessTokenMatch.Success || !sessionCookiesMatch.Success)
                    {
                        throw new Exception("Không tìm thấy access_token hoặc session_cookies");
                    }

                    string accessToken = accessTokenMatch.Groups[1].Value;
                    string cookiesJson = $"[{sessionCookiesMatch.Groups[1].Value}]";
                    var cookiesArray = JArray.Parse(cookiesJson);

                    List<string> cookieParts = new List<string>();
                    foreach (var cookie in cookiesArray)
                    {
                        string name = cookie["name"].Value<string>();
                        string value = cookie["value"].Value<string>();
                        cookieParts.Add($"{name}={value}");
                    }
                    string cookies = string.Join("; ", cookieParts);

                    Console.WriteLine("Cookies: " + cookies);
                    Console.WriteLine("Access Token: " + accessToken);

 
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Lỗi khi xử lý response: " + ex.Message);
                }
            }

            else if (responseBody.Contains("chưa kết nối với tài khoản") ||
          responseBodyUnescape.Contains("chưa kết nối với tài khoản"))  // Sai tên tài khoản
            {
                Console.WriteLine("Sai tên tài khoản");
                return;
            }
            else if (responseBody.Contains("Mật khẩu bạn đã nhập không chính xác") ||
         responseBodyUnescape.Contains("Mật khẩu bạn đã nhập không chính xác"))  // Sai mật khẩu
            {
                Console.WriteLine("Sai mật khẩu");
                return;
            }
            else
            {
                Console.WriteLine(responseBodyUnescape);
                Console.WriteLine("Phản hồi chưa xác định");
            }


        }
        catch (HttpRequestException e)
        {
            Console.WriteLine("Yêu cầu thất bại: " + e.Message);
            throw;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Lỗi: {e.Message}");
            Console.WriteLine($"Stack trace: {e.StackTrace}");
            throw;
        }
    }
}
class Program
{
    static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;

        try
        {
            var Username = "haihip.27";
            var Password = "mk11111kitu";
            var string2FA = "L2KL OSOP LWVP 2QM5 CQ4J WNWR GFZM EOFR".Replace(" ", "");


            var fbLogin = new FacebookLogin();
            await fbLogin.LoginAsync(Username, Password, string2FA);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Lỗi trong quá trình login: {ex.Message}");
        }

        Console.ReadLine();
    }
}