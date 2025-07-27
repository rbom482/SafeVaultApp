using System;
using System.Configuration;
using SafeVaultApp.Helpers;
using SafeVaultApp.Services;
using SafeVaultApp.Tests;
using SafeVaultApp.Configuration;
using SafeVaultApp.Logging;
using SafeVaultApp.Features;

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

                // Run authentication and authorization tests
                AuthenticationTests.RunAllTests();

                // Demonstrate secure authentication
                DemonstrateSecureAuthentication(config, logger);

                // Demonstrate role-based authorization
                DemonstrateRoleBasedAuthorization(config, logger);

                // Demonstrate feature access control
                DemonstrateFeatureAccessControl(config, logger);

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

        /// <summary>
        /// Demonstrates role-based authorization (RBAC) functionality.
        /// Shows how different user roles have different access levels.
        /// </summary>
        private static void DemonstrateRoleBasedAuthorization(SecurityConfiguration config, ISecurityLogger logger)
        {
            Console.WriteLine("\n=== Role-Based Authorization Demo ===");

            var authService = new AuthenticationService(config, logger);

            // Test scenarios with different user roles
            var roleTestCases = new[]
            {
                new { Username = "admin", Role = "admin", Description = "Admin user accessing admin features" },
                new { Username = "moderator", Role = "moderator", Description = "Moderator user accessing moderation features" },
                new { Username = "regularuser", Role = "user", Description = "Regular user accessing user features" },
                new { Username = "hacker", Role = "user", Description = "Potential attacker attempting privilege escalation" }
            };

            foreach (var testCase in roleTestCases)
            {
                Console.WriteLine($"\nTesting: {testCase.Description}");
                Console.WriteLine($"Username: {testCase.Username} (Role: {testCase.Role})");

                // Test admin dashboard access
                bool adminAccess = authService.CanAccessAdminDashboard(testCase.Username);
                Console.WriteLine($"Admin Dashboard Access: {(adminAccess ? "✅ GRANTED" : "❌ DENIED")}");

                // Test moderation tools access
                bool moderationAccess = authService.CanAccessModerationTools(testCase.Username);
                Console.WriteLine($"Moderation Tools Access: {(moderationAccess ? "✅ GRANTED" : "❌ DENIED")}");

                // Test role retrieval
                string? userRole = authService.GetUserRole(testCase.Username);
                Console.WriteLine($"Detected Role: {userRole ?? "NOT_FOUND"}");

                // Test authorization for different roles
                bool isAuthorizedAdmin = authService.IsUserAuthorized(testCase.Username, "admin");
                bool isAuthorizedModerator = authService.IsUserAuthorized(testCase.Username, "moderator");
                bool isAuthorizedUser = authService.IsUserAuthorized(testCase.Username, "user");

                Console.WriteLine($"Admin Authorization: {(isAuthorizedAdmin ? "✅" : "❌")}");
                Console.WriteLine($"Moderator Authorization: {(isAuthorizedModerator ? "✅" : "❌")}");
                Console.WriteLine($"User Authorization: {(isAuthorizedUser ? "✅" : "❌")}");
            }
        }

        /// <summary>
        /// Demonstrates feature access control with role-based authorization.
        /// Shows practical examples of protecting different application features.
        /// </summary>
        private static void DemonstrateFeatureAccessControl(SecurityConfiguration config, ISecurityLogger logger)
        {
            Console.WriteLine("\n=== Feature Access Control Demo ===");

            var authService = new AuthenticationService(config, logger);
            var adminDashboard = new AdminDashboard(authService, logger);
            var moderationTools = new ModerationTools(authService, logger);
            var userFeatures = new UserFeatures(authService, logger);

            // Test admin dashboard access
            Console.WriteLine("\n--- Admin Dashboard Access Tests ---");
            Console.WriteLine("Attempting admin dashboard access with different users:");

            var dashboardTestCases = new[]
            {
                new { Username = "admin", ExpectedAccess = true, Description = "Valid admin user" },
                new { Username = "moderator", ExpectedAccess = false, Description = "Moderator user (should be denied)" },
                new { Username = "regularuser", ExpectedAccess = false, Description = "Regular user (should be denied)" },
                new { Username = "attacker", ExpectedAccess = false, Description = "Potential attacker (should be denied)" }
            };

            foreach (var testCase in dashboardTestCases)
            {
                Console.WriteLine($"\nTesting: {testCase.Description}");
                bool hasAccess = adminDashboard.AccessDashboard(testCase.Username);
                string result = hasAccess == testCase.ExpectedAccess ? "✅ CORRECT" : "❌ UNEXPECTED";
                Console.WriteLine($"Result: {result} - Access {(hasAccess ? "granted" : "denied")}");
            }

            // Test moderation tools access
            Console.WriteLine("\n--- Moderation Tools Access Tests ---");
            Console.WriteLine("Attempting moderation tools access with different users:");

            var moderationTestCases = new[]
            {
                new { Username = "admin", ExpectedAccess = true, Description = "Admin user (should have access)" },
                new { Username = "moderator", ExpectedAccess = true, Description = "Moderator user (should have access)" },
                new { Username = "regularuser", ExpectedAccess = false, Description = "Regular user (should be denied)" }
            };

            foreach (var testCase in moderationTestCases)
            {
                Console.WriteLine($"\nTesting: {testCase.Description}");
                bool hasAccess = moderationTools.AccessModerationTools(testCase.Username);
                string result = hasAccess == testCase.ExpectedAccess ? "✅ CORRECT" : "❌ UNEXPECTED";
                Console.WriteLine($"Result: {result} - Access {(hasAccess ? "granted" : "denied")}");
            }

            // Test user dashboard access
            Console.WriteLine("\n--- User Dashboard Access Tests ---");
            Console.WriteLine("Attempting user dashboard access:");

            var userTestCases = new[]
            {
                new { Username = "admin", ExpectedAccess = true, Description = "Admin user" },
                new { Username = "moderator", ExpectedAccess = true, Description = "Moderator user" },
                new { Username = "regularuser", ExpectedAccess = true, Description = "Regular user" },
                new { Username = "nonexistent", ExpectedAccess = false, Description = "Non-existent user (should be denied)" }
            };

            foreach (var testCase in userTestCases)
            {
                Console.WriteLine($"\nTesting: {testCase.Description}");
                bool hasAccess = userFeatures.AccessUserDashboard(testCase.Username);
                string result = hasAccess == testCase.ExpectedAccess ? "✅ CORRECT" : "❌ UNEXPECTED";
                Console.WriteLine($"Result: {result} - Access {(hasAccess ? "granted" : "denied")}");
            }

            // Demonstrate admin-only functions
            Console.WriteLine("\n--- Admin-Only Functions Demo ---");
            Console.WriteLine("Testing role assignment (admin-only operation):");

            bool roleAssignmentSuccess = adminDashboard.AssignUserRole("admin", "testuser", "moderator");
            Console.WriteLine($"Role assignment by admin: {(roleAssignmentSuccess ? "✅ SUCCESS" : "❌ FAILED")}");

            bool unauthorizedRoleAssignment = adminDashboard.AssignUserRole("regularuser", "testuser", "admin");
            Console.WriteLine($"Unauthorized role assignment attempt: {(unauthorizedRoleAssignment ? "❌ SECURITY BREACH" : "✅ PROPERLY BLOCKED")}");
        }
    }
}
