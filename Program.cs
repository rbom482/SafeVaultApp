using System;
using System.Configuration;
using SafeVaultApp.Helpers;
using SafeVaultApp.Services;
using SafeVaultApp.Tests;
using SafeVaultApp.Configuration;
using SafeVaultApp.Logging;

namespace SafeVaultApp
{
    /// <summary>
    /// SafeVault Application - Demonstrates secure coding principles with Microsoft Copilot
    /// Implements input validation, SQL injection prevention, XSS protection, and OWASP guidelines.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== SafeVault Application ===");
            Console.WriteLine("Secure Coding with Microsoft Copilot");
            Console.WriteLine("Implementing OWASP Top 10 Security Guidelines\n");

            // Initialize configuration and logging
            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();

            // Validate configuration
            if (!config.IsValid())
            {
                Console.WriteLine("ERROR: Invalid security configuration. Please check your settings.");
                return;
            }

            logger.LogSecurityEvent("APPLICATION_START", "SafeVault application started", SecurityLogLevel.Info);

            try
            {
                // Run comprehensive security tests
                SecurityTests.RunAllTests();

                // Demonstrate secure authentication
                DemonstrateSecureAuthentication(config, logger);

                // Demonstrate input validation
                DemonstrateInputValidation();

                // Demonstrate XSS protection
                DemonstrateXSSProtection();

                logger.LogSecurityEvent("APPLICATION_END", "SafeVault application completed successfully", SecurityLogLevel.Info);
            }
            catch (Exception ex)
            {
                logger.LogSecurityEvent("APPLICATION_ERROR", $"Unhandled exception: {ex.Message}", SecurityLogLevel.Critical);
                Console.WriteLine($"Application error: {ex.Message}");
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        /// <summary>
        /// Demonstrates secure authentication with input validation and parameterized queries.
        /// </summary>
        private static void DemonstrateSecureAuthentication(SecurityConfiguration config, ISecurityLogger logger)
        {
            Console.WriteLine("\n=== Secure Authentication Demo ===");

            var authService = new AuthenticationService(config, logger);

            // Test cases for secure login
            var testCases = new[]
            {
                new { Username = "validuser", Password = "SecurePass123!", Description = "Valid credentials" },
                new { Username = "user'; DROP TABLE Users; --", Password = "password", Description = "SQL injection attempt" },
                new { Username = "user<script>alert('xss')</script>", Password = "password", Description = "XSS attempt in username" },
                new { Username = "", Password = "password", Description = "Empty username" },
                new { Username = "user", Password = "", Description = "Empty password" }
            };

            foreach (var testCase in testCases)
            {
                Console.WriteLine($"\nTesting: {testCase.Description}");
                Console.WriteLine($"Username: {testCase.Username}");
                Console.WriteLine($"Password: [REDACTED]");

                try
                {
                    bool loginResult = authService.LoginUser(testCase.Username, testCase.Password);
                    Console.WriteLine($"Login Result: {(loginResult ? "SUCCESS" : "FAILED")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Demonstrates comprehensive input validation.
        /// </summary>
        private static void DemonstrateInputValidation()
        {
            Console.WriteLine("\n=== Input Validation Demo ===");

            var testInputs = new[]
            {
                new { Input = "ValidUser123", AllowedChars = "", Description = "Valid alphanumeric" },
                new { Input = "user@domain.com", AllowedChars = "@.", Description = "Valid email format" },
                new { Input = "Password123!", AllowedChars = "!@#$%^&*?", Description = "Valid password" },
                new { Input = "'; DROP TABLE Users; --", AllowedChars = "", Description = "SQL injection" },
                new { Input = "<script>alert('xss')</script>", AllowedChars = "", Description = "XSS attempt" },
                new { Input = "user|rm -rf /", AllowedChars = "", Description = "Command injection" }
            };

            foreach (var test in testInputs)
            {
                bool isValid = ValidationHelpers.IsValidInput(test.Input, test.AllowedChars);
                Console.WriteLine($"Input: {test.Input}");
                Console.WriteLine($"Description: {test.Description}");
                Console.WriteLine($"Valid: {isValid}");
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Demonstrates XSS protection and input sanitization.
        /// </summary>
        private static void DemonstrateXSSProtection()
        {
            Console.WriteLine("\n=== XSS Protection Demo ===");

            // Run the specific XSS test from the guide
            SecurityTests.TestXssInput();

            // Additional XSS protection demonstrations
            var xssTestCases = new[]
            {
                "<script>alert('XSS Attack!');</script>",
                "<img src='x' onerror='alert(\"XSS\")'>",
                "<iframe src='javascript:alert(\"XSS\")'></iframe>",
                "<svg onload='alert(\"XSS\")'>",
                "javascript:alert('XSS')",
                "Hello <b>World</b>", // Safe HTML
                "user@domain.com" // Safe text
            };

            Console.WriteLine("Testing XSS protection on various inputs:");
            foreach (var input in xssTestCases)
            {
                bool isSafe = ValidationHelpers.IsValidXSSInput(input);
                string sanitized = ValidationHelpers.SanitizeInput(input);
                
                Console.WriteLine($"\nOriginal: {input}");
                Console.WriteLine($"Safe: {isSafe}");
                Console.WriteLine($"Sanitized: {sanitized}");
            }
        }
    }
}
