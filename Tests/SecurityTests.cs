using System;
using SafeVaultApp.Helpers;

namespace SafeVaultApp.Tests
{
    /// <summary>
    /// Comprehensive security testing class that validates input validation,
    /// XSS protection, and other security measures. Follows OWASP testing guidelines.
    /// </summary>
    public static class SecurityTests
    {
        /// <summary>
        /// Runs all security tests and reports results.
        /// </summary>
        public static void RunAllTests()
        {
            Console.WriteLine("=== SafeVault Security Testing Suite ===");
            Console.WriteLine("Running comprehensive security tests...\n");

            TestInputValidation();
            TestXSSProtection();
            TestPasswordValidation();
            TestEmailValidation();
            TestInputSanitization();

            Console.WriteLine("\n=== Security Testing Complete ===");
        }

        /// <summary>
        /// Tests input validation functionality against various attack vectors.
        /// </summary>
        public static void TestInputValidation()
        {
            Console.WriteLine("--- Input Validation Tests ---");

            // Test valid inputs
            TestValidationCase("ValidUser123", "", true, "Valid alphanumeric username");
            TestValidationCase("user@domain.com", "@.", true, "Valid email-like input");
            TestValidationCase("Password123!", "!@#$%^&*?", true, "Valid password with allowed specials");

            // Test invalid inputs
            TestValidationCase("", "", false, "Empty string");
            TestValidationCase("user'; DROP TABLE Users; --", "", false, "SQL injection attempt");
            TestValidationCase("user<script>alert('xss')</script>", "", false, "XSS attempt in validation");
            TestValidationCase("user|rm -rf /", "", false, "Command injection attempt");

            Console.WriteLine();
        }

        /// <summary>
        /// Tests XSS protection against various cross-site scripting attempts.
        /// </summary>
        public static void TestXSSProtection()
        {
            Console.WriteLine("--- XSS Protection Tests ---");

            // Test safe inputs
            TestXSSCase("Hello World", true, "Safe text input");
            TestXSSCase("user@domain.com", true, "Email address");
            TestXSSCase("", true, "Empty string");

            // Test malicious inputs
            TestXSSCase("<script>alert('XSS');</script>", false, "Basic script tag");
            TestXSSCase("<SCRIPT>alert('XSS');</SCRIPT>", false, "Uppercase script tag");
            TestXSSCase("<iframe src='javascript:alert(\"XSS\")'></iframe>", false, "Iframe with javascript");
            TestXSSCase("<object data='data:text/html,<script>alert(\"XSS\")</script>'></object>", false, "Object tag");
            TestXSSCase("<img src='x' onerror='alert(\"XSS\")'/>", false, "Event handler injection");
            TestXSSCase("javascript:alert('XSS')", false, "JavaScript protocol");
            TestXSSCase("<meta http-equiv='refresh' content='0;url=javascript:alert(\"XSS\")'>", false, "Meta refresh XSS");

            Console.WriteLine();
        }

        /// <summary>
        /// Tests password validation requirements.
        /// </summary>
        public static void TestPasswordValidation()
        {
            Console.WriteLine("--- Password Validation Tests ---");

            // Test valid passwords
            TestPasswordCase("Password123!", 8, true, "Strong password with all requirements");
            TestPasswordCase("MySecure@Pass1", 8, true, "Another strong password");

            // Test invalid passwords
            TestPasswordCase("password", 8, false, "No uppercase, digits, or specials");
            TestPasswordCase("PASSWORD123!", 8, false, "No lowercase letters");
            TestPasswordCase("Password!", 8, false, "No digits");
            TestPasswordCase("Password123", 8, false, "No special characters");
            TestPasswordCase("Pass1!", 8, false, "Too short");
            TestPasswordCase("", 8, false, "Empty password");

            Console.WriteLine();
        }

        /// <summary>
        /// Tests email validation functionality.
        /// </summary>
        public static void TestEmailValidation()
        {
            Console.WriteLine("--- Email Validation Tests ---");

            // Test valid emails
            TestEmailCase("user@domain.com", true, "Standard email format");
            TestEmailCase("test.email@example.org", true, "Email with dot in local part");
            TestEmailCase("user+tag@domain.co.uk", true, "Email with plus and multiple domains");

            // Test invalid emails
            TestEmailCase("invalid-email", false, "Missing @ symbol");
            TestEmailCase("@domain.com", false, "Missing local part");
            TestEmailCase("user@", false, "Missing domain");
            TestEmailCase("user@domain", false, "Missing TLD");
            TestEmailCase("", false, "Empty email");

            Console.WriteLine();
        }

        /// <summary>
        /// Tests input sanitization functionality.
        /// </summary>
        public static void TestInputSanitization()
        {
            Console.WriteLine("--- Input Sanitization Tests ---");

            // Test sanitization of malicious content
            TestSanitizationCase(
                "<script>alert('XSS')</script>Hello World",
                "Hello World",
                "Script tag removal");

            TestSanitizationCase(
                "<iframe src='evil.com'></iframe>Safe Content",
                "Safe Content",
                "Iframe tag removal");

            TestSanitizationCase(
                "<div onclick='alert(\"XSS\")'>Click me</div>",
                "<div>Click me</div>",
                "Event handler removal");

            TestSanitizationCase(
                "Normal text without threats",
                "Normal text without threats",
                "Safe content unchanged");

            Console.WriteLine();
        }

        /// <summary>
        /// Helper method to test validation cases.
        /// </summary>
        private static void TestValidationCase(string input, string allowedChars, bool expected, string description)
        {
            bool result = ValidationHelpers.IsValidInput(input, allowedChars);
            string status = result == expected ? "PASS" : "FAIL";
            Console.WriteLine($"  [{status}] {description}: {result}");
        }

        /// <summary>
        /// Helper method to test XSS protection cases.
        /// </summary>
        private static void TestXSSCase(string input, bool expected, string description)
        {
            bool result = ValidationHelpers.IsValidXSSInput(input);
            string status = result == expected ? "PASS" : "FAIL";
            Console.WriteLine($"  [{status}] {description}: {result}");
        }

        /// <summary>
        /// Helper method to test password validation cases.
        /// </summary>
        private static void TestPasswordCase(string password, int minLength, bool expected, string description)
        {
            bool result = ValidationHelpers.IsValidPassword(password, minLength);
            string status = result == expected ? "PASS" : "FAIL";
            Console.WriteLine($"  [{status}] {description}: {result}");
        }

        /// <summary>
        /// Helper method to test email validation cases.
        /// </summary>
        private static void TestEmailCase(string email, bool expected, string description)
        {
            bool result = ValidationHelpers.IsValidEmail(email);
            string status = result == expected ? "PASS" : "FAIL";
            Console.WriteLine($"  [{status}] {description}: {result}");
        }

        /// <summary>
        /// Helper method to test input sanitization cases.
        /// </summary>
        private static void TestSanitizationCase(string input, string expected, string description)
        {
            string result = ValidationHelpers.SanitizeInput(input);
            bool matches = string.Equals(result.Trim(), expected.Trim(), StringComparison.OrdinalIgnoreCase);
            string status = matches ? "PASS" : "FAIL";
            Console.WriteLine($"  [{status}] {description}");
            if (!matches)
            {
                Console.WriteLine($"    Expected: '{expected}'");
                Console.WriteLine($"    Got:      '{result}'");
            }
        }

        /// <summary>
        /// Demonstrates XSS testing as mentioned in the guide.
        /// </summary>
        public static void TestXssInput()
        {
            Console.WriteLine("--- XSS Input Test (from guide) ---");
            
            string maliciousInput = "<script>alert('XSS');</script>";
            bool isValid = ValidationHelpers.IsValidXSSInput(maliciousInput);
            Console.WriteLine(isValid ? "XSS Test Failed" : "XSS Test Passed");
            
            // Additional comprehensive XSS tests
            string[] xssPayloads = {
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src='data:text/html,<script>alert(\"XSS\")</script>'></iframe>",
                "<object data='javascript:alert(\"XSS\")'></object>"
            };

            Console.WriteLine("\nTesting additional XSS payloads:");
            foreach (string payload in xssPayloads)
            {
                bool safe = ValidationHelpers.IsValidXSSInput(payload);
                Console.WriteLine($"  Payload blocked: {!safe} - {payload.Substring(0, Math.Min(50, payload.Length))}...");
            }

            Console.WriteLine();
        }
    }
}
