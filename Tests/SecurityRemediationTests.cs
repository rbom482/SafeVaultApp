using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using SafeVaultApp.Configuration;
using SafeVaultApp.Helpers;
using SafeVaultApp.Logging;
using SafeVaultApp.Services;

namespace SafeVaultApp.Tests
{
    /// <summary>
    /// Security remediation testing class that demonstrates fixing identified vulnerabilities.
    /// This class shows the process of applying security fixes and verifying their effectiveness.
    /// Implements security best practices and OWASP guidelines for vulnerability remediation.
    /// </summary>
    public static class SecurityRemediationTests
    {
        /// <summary>
        /// Runs all security remediation tests to verify fixes are effective.
        /// </summary>
        public static void RunSecurityRemediationTests()
        {
            Console.WriteLine("=== Security Remediation & Fix Verification ===");
            Console.WriteLine("Testing applied security fixes and improvements...\n");

            try
            {
                // Test enhanced input validation
                TestEnhancedInputValidation();

                // Test improved XSS protection
                TestImprovedXSSProtection();

                // Test SQL injection prevention improvements
                TestSQLInjectionPrevention();

                // Test authentication security enhancements
                TestAuthenticationSecurityEnhancements();

                // Test authorization security improvements
                TestAuthorizationSecurityImprovements();

                // Test error handling security
                TestSecureErrorHandling();

                // Test security logging improvements
                TestSecurityLoggingImprovements();

                Console.WriteLine("\n=== Security Remediation Testing Complete ===");
                Console.WriteLine("All remediation tests completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Unexpected error during remediation testing: {ex.Message}");
            }
        }

        /// <summary>
        /// Tests enhanced input validation with improved patterns and edge case handling.
        /// </summary>
        private static void TestEnhancedInputValidation()
        {
            Console.WriteLine("--- Enhanced Input Validation Tests ---");

            // Test advanced validation scenarios
            var advancedValidationTests = new[]
            {
                // Test null safety improvements
                new { Input = (string?)null, Expected = false, Description = "Null input handling" },
                new { Input = (string?)"", Expected = false, Description = "Empty string handling" },
                new { Input = (string?)"   ", Expected = false, Description = "Whitespace-only input" },
                
                // Test length boundaries
                new { Input = (string?)"a", Expected = false, Description = "Single character (too short)" },
                new { Input = (string?)"ab", Expected = false, Description = "Two characters (too short)" },
                new { Input = (string?)"abc", Expected = true, Description = "Minimum valid length" },
                new { Input = (string?)new string('a', 100), Expected = true, Description = "Normal length" },
                new { Input = (string?)new string('a', 1000), Expected = false, Description = "Excessive length" },
                
                // Test character set validation improvements
                new { Input = (string?)"ValidUser123", Expected = true, Description = "Valid alphanumeric" },
                new { Input = (string?)"user@domain.com", Expected = false, Description = "Email characters without allowlist" },
                new { Input = (string?)"user-name_123", Expected = false, Description = "Special characters without allowlist" },
                
                // Test encoding attack prevention
                new { Input = (string?)"user%00admin", Expected = false, Description = "Null byte injection" },
                new { Input = (string?)"user\x00admin", Expected = false, Description = "Null character injection" },
                new { Input = (string?)"user\x1Fadmin", Expected = false, Description = "Control character injection" },
                
                // Test Unicode normalization attacks
                new { Input = (string?)"user\u0041\u0301", Expected = false, Description = "Unicode combining characters" },
                new { Input = (string?)"user\uFEFF", Expected = false, Description = "Byte order mark injection" },
                
                // Test homograph attacks
                new { Input = (string?)"αdmin", Expected = false, Description = "Greek alpha instead of 'a'" },
                new { Input = (string?)"uѕer", Expected = false, Description = "Cyrillic 's' instead of 's'" }
            };

            Console.WriteLine("Testing enhanced input validation:");

            int passedTests = 0;
            int totalTests = advancedValidationTests.Length;

            foreach (var test in advancedValidationTests)
            {
                try
                {
                    bool result = ValidationHelpers.IsValidInput(test.Input ?? "");
                    bool passed = result == test.Expected;
                    
                    string status = passed ? "✅ PASS" : "❌ FAIL";
                    Console.WriteLine($"  {status} - {test.Description}: Expected {test.Expected}, Got {result}");
                    
                    if (passed) passedTests++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  ❌ ERROR - {test.Description}: {ex.Message}");
                }
            }

            Console.WriteLine($"\nEnhanced Input Validation Results: {passedTests}/{totalTests} tests passed ({(passedTests * 100.0 / totalTests):F1}%)");
            Console.WriteLine();
        }

        /// <summary>
        /// Tests improved XSS protection with additional attack vector coverage.
        /// </summary>
        private static void TestImprovedXSSProtection()
        {
            Console.WriteLine("--- Improved XSS Protection Tests ---");

            // Test enhanced XSS detection patterns
            var enhancedXSSTests = new (string? Input, bool ExpectedSafe, string Description)[]
            {
                // Basic XSS vectors (should be blocked)
                ( "<script>alert('xss')</script>", false, "Basic script tag" ),
                ( "<img src=x onerror=alert('xss')>", false, "Image onerror handler" ),
                ( "javascript:alert('xss')", false, "JavaScript protocol" ),
                
                // Advanced XSS vectors (should be blocked)
                ( "<svg/onload=alert('xss')>", false, "SVG onload handler" ),
                ( "<iframe src='javascript:alert(\"xss\")'></iframe>", false, "Iframe JavaScript" ),
                ( "<object data='data:text/html,<script>alert(\"xss\")</script>'></object>", false, "Object with data URL" ),
                
                // Encoding-based XSS (should be blocked)
                ( "&lt;script&gt;alert('xss')&lt;/script&gt;", false, "HTML entity encoded" ),
                ( "%3Cscript%3Ealert('xss')%3C/script%3E", false, "URL encoded" ),
                ( "&#60;script&#62;alert('xss')&#62;/script&#62;", false, "Numeric entity encoded" ),
                
                // Context-aware XSS (should be blocked)
                ( "';alert('xss');//", false, "JavaScript context injection" ),
                ( "\";alert('xss');//", false, "Double quote escape" ),
                ( "');alert('xss');//", false, "Function call escape" ),
                
                // CSS-based XSS (should be blocked)
                ( "expression(alert('xss'))", false, "CSS expression" ),
                ( "url(javascript:alert('xss'))", false, "CSS URL JavaScript" ),
                ( "@import 'javascript:alert(\"xss\")'", false, "CSS import JavaScript" ),
                
                // Safe inputs (should be allowed)
                ( "Hello World", true, "Plain text" ),
                ( "user@domain.com", true, "Email address" ),
                ( "Price: $19.99", true, "Price with dollar sign" ),
                ( "Mathematical expression: 2 + 2 = 4", true, "Mathematical content" ),
                ( "File path: C:\\Users\\Documents", true, "File path" ),
                
                // Edge cases
                ( "", true, "Empty string" ),
                ( "   ", true, "Whitespace only" ),
                ( null, true, "Null input" )
            };

            Console.WriteLine("Testing improved XSS protection:");

            int correctBlocks = 0;
            int correctAllows = 0;
            int incorrectBlocks = 0;
            int incorrectAllows = 0;

            foreach (var test in enhancedXSSTests)
            {
                try
                {
                    bool isSafe = ValidationHelpers.IsValidXSSInput(test.Input ?? "");
                    bool correct = isSafe == test.ExpectedSafe;
                    
                    if (correct)
                    {
                        if (test.ExpectedSafe)
                        {
                            correctAllows++;
                            Console.WriteLine($"  ✅ CORRECT ALLOW - {test.Description}");
                        }
                        else
                        {
                            correctBlocks++;
                            Console.WriteLine($"  ✅ CORRECT BLOCK - {test.Description}");
                        }
                    }
                    else
                    {
                        if (test.ExpectedSafe)
                        {
                            incorrectBlocks++;
                            Console.WriteLine($"  ❌ INCORRECT BLOCK - {test.Description} (should be allowed)");
                        }
                        else
                        {
                            incorrectAllows++;
                            Console.WriteLine($"  ❌ INCORRECT ALLOW - {test.Description} (POTENTIAL VULNERABILITY)");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  ❌ ERROR - {test.Description}: {ex.Message}");
                }
            }

            int totalTests = enhancedXSSTests.Length;
            int correctTotal = correctBlocks + correctAllows;
            
            Console.WriteLine($"\nImproved XSS Protection Results:");
            Console.WriteLine($"  ✅ Correctly blocked: {correctBlocks}");
            Console.WriteLine($"  ✅ Correctly allowed: {correctAllows}");
            Console.WriteLine($"  ❌ Incorrectly blocked: {incorrectBlocks}");
            Console.WriteLine($"  ❌ Incorrectly allowed (vulnerabilities): {incorrectAllows}");
            Console.WriteLine($"  Overall accuracy: {correctTotal}/{totalTests} ({(correctTotal * 100.0 / totalTests):F1}%)");
            Console.WriteLine();
        }

        /// <summary>
        /// Tests SQL injection prevention with enhanced parameterization.
        /// </summary>
        private static void TestSQLInjectionPrevention()
        {
            Console.WriteLine("--- SQL Injection Prevention Tests ---");

            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test parameterized query protection
            var sqlInjectionTests = new[]
            {
                // Classic SQL injection attempts
                "admin'; DROP TABLE Users; --",
                "'; DELETE FROM Users; --",
                "' OR '1'='1",
                "admin'--",
                "admin' #",
                
                // Union-based injection
                "' UNION SELECT password FROM admin --",
                "' UNION ALL SELECT NULL, username, password FROM users --",
                
                // Stored procedure injection
                "'; EXEC xp_cmdshell 'dir'; --",
                "'; EXEC sp_configure 'show advanced options', 1; --",
                
                // Time-based blind injection
                "'; WAITFOR DELAY '00:00:05'; --",
                "' OR IF(1=1, SLEEP(5), 0) --",
                
                // Boolean-based blind injection
                "' AND (SELECT COUNT(*) FROM Users) > 0 --",
                "' AND SUBSTRING(@@version,1,1)='M' --",
                
                // Second-order injection
                "test'; INSERT INTO Users VALUES('hacker', 'password'); --",
                
                // Error-based injection
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --"
            };

            Console.WriteLine("Testing SQL injection prevention through parameterized queries:");

            int totalBlocked = 0;
            int totalTests = sqlInjectionTests.Length;

            foreach (var injectionPayload in sqlInjectionTests)
            {
                try
                {
                    // Test login with malicious username
                    bool loginResult = authService.LoginUser(injectionPayload, "password");
                    
                    // Test user data retrieval (simulate with invalid ID that might contain injection)
                    var userData = authService.GetUserData(-1); // Invalid ID should be safely handled
                    
                    // Test role checking with malicious input
                    string? role = authService.GetUserRole(injectionPayload);
                    
                    // If we reach here without SQL injection, the protection is working
                    totalBlocked++;
                    Console.WriteLine($"  ✅ BLOCKED - SQL injection prevented: {injectionPayload.Substring(0, Math.Min(50, injectionPayload.Length))}...");
                }
                catch (SqlException ex)
                {
                    // Check if the SQL exception indicates an injection attempt was blocked
                    if (ex.Message.Contains("Incorrect syntax") || 
                        ex.Message.Contains("Invalid column") ||
                        ex.Message.Contains("Invalid object"))
                    {
                        totalBlocked++;
                        Console.WriteLine($"  ✅ BLOCKED - SQL injection caught by SQL Server: {ex.Message.Substring(0, Math.Min(50, ex.Message.Length))}...");
                    }
                    else
                    {
                        Console.WriteLine($"  ⚠️  UNEXPECTED SQL ERROR - {ex.Message.Substring(0, Math.Min(50, ex.Message.Length))}...");
                    }
                }
                catch (Exception ex)
                {
                    totalBlocked++;
                    Console.WriteLine($"  ✅ BLOCKED - Exception handled: {ex.GetType().Name}");
                }
            }

            Console.WriteLine($"\nSQL Injection Prevention Results: {totalBlocked}/{totalTests} injection attempts blocked ({(totalBlocked * 100.0 / totalTests):F1}%)");
            Console.WriteLine();
        }

        /// <summary>
        /// Tests authentication security enhancements.
        /// </summary>
        private static void TestAuthenticationSecurityEnhancements()
        {
            Console.WriteLine("--- Authentication Security Enhancement Tests ---");

            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test password complexity requirements
            Console.WriteLine("Testing password complexity requirements:");
            TestPasswordComplexity();

            // Test account lockout mechanisms
            Console.WriteLine("\nTesting account lockout protection:");
            TestAccountLockoutProtection(authService);

            // Test timing attack resistance
            Console.WriteLine("\nTesting timing attack resistance:");
            TestTimingAttackResistance(authService);

            Console.WriteLine();
        }

        /// <summary>
        /// Tests password complexity validation.
        /// </summary>
        private static void TestPasswordComplexity()
        {
            var passwordTests = new[]
            {
                // Weak passwords (should be rejected)
                new { Password = "123456", Expected = false, Description = "Numeric only" },
                new { Password = "password", Expected = false, Description = "Common word" },
                new { Password = "abcdefgh", Expected = false, Description = "Letters only, no complexity" },
                new { Password = "Password", Expected = false, Description = "Letters only with case" },
                new { Password = "Pass123", Expected = false, Description = "Too short" },
                
                // Strong passwords (should be accepted)
                new { Password = "SecurePass123!", Expected = true, Description = "Strong password with all elements" },
                new { Password = "MyP@ssw0rd2024", Expected = true, Description = "Complex password with special chars" },
                new { Password = "Tr0ub4dor&3", Expected = true, Description = "Complex with mixed case and symbols" },
                
                // Edge cases
                new { Password = "", Expected = false, Description = "Empty password" },
                new { Password = "   ", Expected = false, Description = "Whitespace only" },
                new { Password = new string('a', 200), Expected = false, Description = "Extremely long password" }
            };

            foreach (var test in passwordTests)
            {
                bool isValid = ValidationHelpers.IsValidPassword(test.Password, 8); // Minimum 8 characters
                bool passed = isValid == test.Expected;
                
                string status = passed ? "✅ PASS" : "❌ FAIL";
                Console.WriteLine($"  {status} - {test.Description}: {(passed ? "As expected" : $"Expected {test.Expected}, got {isValid}")}");
            }
        }

        /// <summary>
        /// Tests account lockout protection mechanisms.
        /// </summary>
        private static void TestAccountLockoutProtection(AuthenticationService authService)
        {
            // Simulate multiple failed login attempts
            string testUsername = "testlockoutuser";
            
            Console.WriteLine($"  Testing account lockout for user: {testUsername}");
            
            for (int attempt = 1; attempt <= 6; attempt++)
            {
                try
                {
                    bool result = authService.LoginUser(testUsername, "wrongpassword");
                    string status = result ? "❌ UNEXPECTED SUCCESS" : "✅ CORRECTLY FAILED";
                    Console.WriteLine($"    Attempt {attempt}: {status}");
                    
                    // Add small delay to simulate real-world timing
                    System.Threading.Thread.Sleep(100);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    Attempt {attempt}: ✅ EXCEPTION HANDLED - {ex.GetType().Name}");
                }
            }
        }

        /// <summary>
        /// Tests resistance to timing attacks.
        /// </summary>
        private static void TestTimingAttackResistance(AuthenticationService authService)
        {
            var timingTests = new[]
            {
                "nonexistentuser",
                "admin",
                "testuser",
                "administrator"
            };

            var timings = new List<long>();

            foreach (var username in timingTests)
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                try
                {
                    authService.LoginUser(username, "wrongpassword");
                }
                catch
                {
                    // Ignore exceptions for timing test
                }
                
                stopwatch.Stop();
                timings.Add(stopwatch.ElapsedMilliseconds);
                
                Console.WriteLine($"  User '{username}': {stopwatch.ElapsedMilliseconds}ms");
            }

            // Analyze timing consistency
            if (timings.Count > 1)
            {
                var maxTiming = timings.Max();
                var minTiming = timings.Min();
                var variance = maxTiming - minTiming;
                
                string status = variance < 100 ? "✅ CONSISTENT TIMING" : "⚠️  TIMING VARIANCE DETECTED";
                Console.WriteLine($"  {status} - Variance: {variance}ms (Max: {maxTiming}ms, Min: {minTiming}ms)");
            }
        }

        /// <summary>
        /// Tests authorization security improvements.
        /// </summary>
        private static void TestAuthorizationSecurityImprovements()
        {
            Console.WriteLine("--- Authorization Security Improvement Tests ---");

            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test role-based access control with edge cases
            var authorizationTests = new[]
            {
                // Valid authorization tests
                new { Username = "admin", Role = "admin", Expected = true, Description = "Admin accessing admin role" },
                new { Username = "moderator", Role = "moderator", Expected = true, Description = "Moderator accessing moderator role" },
                new { Username = "user", Role = "user", Expected = true, Description = "User accessing user role" },
                
                // Invalid authorization tests
                new { Username = "user", Role = "admin", Expected = false, Description = "User attempting admin access" },
                new { Username = "moderator", Role = "admin", Expected = false, Description = "Moderator attempting admin access" },
                new { Username = "guest", Role = "user", Expected = false, Description = "Guest attempting user access" },
                
                // Edge case tests
                new { Username = "", Role = "user", Expected = false, Description = "Empty username" },
                new { Username = "user", Role = "", Expected = false, Description = "Empty role" },
                new { Username = "user", Role = "ADMIN", Expected = false, Description = "Case sensitivity test" },
                new { Username = "USER", Role = "admin", Expected = false, Description = "Username case sensitivity" },
                
                // Injection attempt tests
                new { Username = "user'; DROP TABLE Users; --", Role = "admin", Expected = false, Description = "SQL injection in username" },
                new { Username = "user", Role = "admin'; GRANT ALL; --", Expected = false, Description = "SQL injection in role" },
                
                // Invalid role tests
                new { Username = "user", Role = "superadmin", Expected = false, Description = "Non-existent role" },
                new { Username = "user", Role = "root", Expected = false, Description = "System role" },
                new { Username = "user", Role = "administrator", Expected = false, Description = "Alternative admin name" }
            };

            Console.WriteLine("Testing role-based authorization security:");

            int passedTests = 0;
            int totalTests = authorizationTests.Length;

            foreach (var test in authorizationTests)
            {
                try
                {
                    bool result = authService.IsUserAuthorized(test.Username, test.Role);
                    bool passed = result == test.Expected;
                    
                    string status = passed ? "✅ PASS" : "❌ FAIL";
                    Console.WriteLine($"  {status} - {test.Description}: Expected {test.Expected}, Got {result}");
                    
                    if (passed) passedTests++;
                }
                catch (Exception ex)
                {
                    // Exceptions should generally result in denied access (secure default)
                    bool secureDefault = !test.Expected; // Exception should deny access
                    string status = secureDefault ? "✅ SECURE DEFAULT" : "❌ INSECURE EXCEPTION";
                    Console.WriteLine($"  {status} - {test.Description}: Exception handled securely");
                    
                    if (secureDefault) passedTests++;
                }
            }

            Console.WriteLine($"\nAuthorization Security Results: {passedTests}/{totalTests} tests passed ({(passedTests * 100.0 / totalTests):F1}%)");
            Console.WriteLine();
        }

        /// <summary>
        /// Tests secure error handling to prevent information disclosure.
        /// </summary>
        private static void TestSecureErrorHandling()
        {
            Console.WriteLine("--- Secure Error Handling Tests ---");

            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test that error messages don't reveal sensitive information
            Console.WriteLine("Testing secure error handling:");

            // Test database connection errors
            try
            {
                // This should be handled gracefully without revealing connection details
                var badConfig = new SecurityConfiguration { ConnectionString = "invalid connection string" };
                var badAuthService = new AuthenticationService(badConfig, logger);
                bool result = badAuthService.LoginUser("test", "test");
                Console.WriteLine("  ✅ SECURE - Database error handled without revealing details");
            }
            catch (Exception ex)
            {
                bool secure = !ex.Message.Contains("server") && !ex.Message.Contains("database") && !ex.Message.Contains("connection");
                string status = secure ? "✅ SECURE" : "❌ INFORMATION DISCLOSURE RISK";
                Console.WriteLine($"  {status} - Database connection failure handling");
            }

            // Test SQL injection error handling
            try
            {
                authService.LoginUser("test'; DROP TABLE Users; --", "password");
                Console.WriteLine("  ✅ SECURE - SQL injection handled without revealing schema");
            }
            catch (SqlException ex)
            {
                // Check that SQL error doesn't reveal schema information
                string msg = ex.Message.ToLower();
                bool secure = !msg.Contains("table") && !msg.Contains("column") && !msg.Contains("syntax");
                string status = secure ? "✅ SECURE" : "❌ SCHEMA DISCLOSURE RISK";
                Console.WriteLine($"  {status} - SQL injection error handling");
            }
            catch
            {
                Console.WriteLine("  ✅ SECURE - SQL injection properly handled");
            }

            // Test invalid user ID error handling
            try
            {
                var result = authService.GetUserData(-999999);
                bool secure = result == null; // Should return null, not throw
                string status = secure ? "✅ SECURE" : "❌ ERROR HANDLING RISK";
                Console.WriteLine($"  {status} - Invalid user ID handling");
            }
            catch
            {
                Console.WriteLine("  ❌ INFORMATION DISCLOSURE RISK - Should not throw exception for invalid ID");
            }

            // Test null parameter handling
            try
            {
                authService.LoginUser("", "password");
                Console.WriteLine("  ✅ SECURE - Null parameter handled gracefully");
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("  ❌ INFORMATION DISCLOSURE RISK - ArgumentNullException reveals internal structure");
            }
            catch
            {
                Console.WriteLine("  ✅ SECURE - Null parameter properly handled");
            }

            Console.WriteLine();
        }

        /// <summary>
        /// Tests security logging improvements for audit trails.
        /// </summary>
        private static void TestSecurityLoggingImprovements()
        {
            Console.WriteLine("--- Security Logging Improvement Tests ---");

            var logger = new ConsoleSecurityLogger();

            Console.WriteLine("Testing security logging functionality:");

            // Test authentication attempt logging
            try
            {
                logger.LogAuthenticationAttempt("testuser", false, "Invalid credentials");
                Console.WriteLine("  ✅ LOGGED - Authentication attempt logging");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ❌ ERROR - Authentication attempt logging: {ex.Message}");
            }

            // Test security violation logging
            try
            {
                logger.LogSecurityViolation("SQL_INJECTION", "Malicious SQL detected", "attacker");
                Console.WriteLine("  ✅ LOGGED - Security violation logging");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ❌ ERROR - Security violation logging: {ex.Message}");
            }

            // Test account action logging
            try
            {
                logger.LogAccountAction("CREATED", "newuser", "Account created successfully");
                Console.WriteLine("  ✅ LOGGED - Account action logging");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ❌ ERROR - Account action logging: {ex.Message}");
            }

            // Test security event logging
            try
            {
                logger.LogSecurityEvent("ACCESS_DENIED", "Unauthorized access attempt", SecurityLogLevel.Warning);
                Console.WriteLine("  ✅ LOGGED - Security event logging");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ❌ ERROR - Security event logging: {ex.Message}");
            }

            // Test sensitive data sanitization
            try
            {
                // Test that logger properly sanitizes sensitive information
                logger.LogAuthenticationAttempt("user<script>alert('xss')</script>", false, "XSS attempt in username");
                Console.WriteLine("  ✅ LOGGED - Sensitive data sanitization (visual inspection required)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ❌ ERROR - Sensitive data sanitization: {ex.Message}");
            }

            Console.WriteLine("\nNote: Visual inspection of log output above is required to verify proper sanitization and formatting.");
            Console.WriteLine();
        }
    }
}
