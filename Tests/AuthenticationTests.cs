using System;
using SafeVaultApp.Services;
using SafeVaultApp.Configuration;
using SafeVaultApp.Logging;

namespace SafeVaultApp.Tests
{
    /// <summary>
    /// Comprehensive authentication and authorization testing class.
    /// Validates login security, role-based access control, and security measures.
    /// Follows OWASP testing guidelines for authentication systems.
    /// </summary>
    public static class AuthenticationTests
    {
        /// <summary>
        /// Runs all authentication and authorization tests.
        /// </summary>
        public static void RunAllTests()
        {
            Console.WriteLine("=== Authentication and Authorization Tests ===\n");

            // Test authentication functionality
            TestUserAuthentication();
            
            // Test role-based authorization
            TestRoleBasedAuthorization();
            
            // Test security attack scenarios
            TestSecurityAttackScenarios();
            
            // Test admin functionality
            TestAdminFunctionality();
            
            // Test feature access control
            TestFeatureAccessControl();

            Console.WriteLine("Authentication and Authorization tests completed.\n");
        }

        /// <summary>
        /// Tests user authentication with various scenarios.
        /// </summary>
        private static void TestUserAuthentication()
        {
            Console.WriteLine("--- User Authentication Tests ---");

            var config = new SecurityConfiguration
            {
                ConnectionString = "Server=localhost;Database=SafeVaultDB;Integrated Security=true;",
                MinPasswordLength = 8,
                HashIterations = 10000,
                SaltLength = 32,
                AllowedSpecialCharacters = "!@#$%^&*?"
            };
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test valid login scenarios
            Console.WriteLine("Testing valid authentication scenarios:");
            TestAuthenticationCase(authService, "validuser", "SecurePass123!", true, "Valid credentials");
            TestAuthenticationCase(authService, "admin", "AdminPass456!", true, "Valid admin credentials");

            // Test invalid login scenarios
            Console.WriteLine("\nTesting invalid authentication scenarios:");
            TestAuthenticationCase(authService, "invaliduser", "wrongpass", false, "Invalid username");
            TestAuthenticationCase(authService, "validuser", "wrongpass", false, "Invalid password");
            TestAuthenticationCase(authService, "", "password", false, "Empty username");
            TestAuthenticationCase(authService, "user", "", false, "Empty password");

            // Test SQL injection attempts
            Console.WriteLine("\nTesting SQL injection prevention:");
            TestAuthenticationCase(authService, "user'; DROP TABLE Users; --", "password", false, "SQL injection in username");
            TestAuthenticationCase(authService, "user", "pass'; DELETE FROM Users; --", false, "SQL injection in password");

            // Test XSS attempts
            Console.WriteLine("\nTesting XSS prevention:");
            TestAuthenticationCase(authService, "user<script>alert('xss')</script>", "password", false, "XSS in username");
            TestAuthenticationCase(authService, "user", "pass<script>alert('xss')</script>", false, "XSS in password");

            Console.WriteLine();
        }

        /// <summary>
        /// Tests role-based authorization functionality.
        /// </summary>
        private static void TestRoleBasedAuthorization()
        {
            Console.WriteLine("--- Role-Based Authorization Tests ---");

            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test role retrieval
            Console.WriteLine("Testing role retrieval:");
            TestRoleRetrieval(authService, "admin", "admin", "Admin user role");
            TestRoleRetrieval(authService, "moderator", "moderator", "Moderator user role");
            TestRoleRetrieval(authService, "regularuser", "user", "Regular user role");
            TestRoleRetrieval(authService, "nonexistent", null, "Non-existent user");

            // Test authorization checks
            Console.WriteLine("\nTesting authorization checks:");
            TestAuthorizationCase(authService, "admin", "admin", true, "Admin accessing admin feature");
            TestAuthorizationCase(authService, "admin", "moderator", true, "Admin accessing moderator feature");
            TestAuthorizationCase(authService, "admin", "user", true, "Admin accessing user feature");
            
            TestAuthorizationCase(authService, "moderator", "admin", false, "Moderator accessing admin feature");
            TestAuthorizationCase(authService, "moderator", "moderator", true, "Moderator accessing moderator feature");
            TestAuthorizationCase(authService, "moderator", "user", true, "Moderator accessing user feature");
            
            TestAuthorizationCase(authService, "regularuser", "admin", false, "User accessing admin feature");
            TestAuthorizationCase(authService, "regularuser", "moderator", false, "User accessing moderator feature");
            TestAuthorizationCase(authService, "regularuser", "user", true, "User accessing user feature");

            Console.WriteLine();
        }

        /// <summary>
        /// Tests security attack scenarios and defenses.
        /// </summary>
        private static void TestSecurityAttackScenarios()
        {
            Console.WriteLine("--- Security Attack Scenario Tests ---");

            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test privilege escalation attempts
            Console.WriteLine("Testing privilege escalation prevention:");
            TestPrivilegeEscalation(authService, "regularuser", "admin", false, "User trying to access admin functions");
            TestPrivilegeEscalation(authService, "regularuser", "moderator", false, "User trying to access moderator functions");

            // Test role manipulation attempts
            Console.WriteLine("\nTesting role manipulation prevention:");
            TestRoleUpdate(authService, "regularuser", "targetuser", "admin", false, "Non-admin attempting role change");
            TestRoleUpdate(authService, "admin", "targetuser", "admin", true, "Admin performing valid role change");
            TestRoleUpdate(authService, "admin", "targetuser", "invalidrole", false, "Admin using invalid role");

            // Test input validation in authorization
            Console.WriteLine("\nTesting input validation in authorization:");
            TestAuthorizationCase(authService, "user'; DROP TABLE Users; --", "admin", false, "SQL injection in authorization");
            TestAuthorizationCase(authService, "user<script>alert('xss')</script>", "admin", false, "XSS in authorization");

            Console.WriteLine();
        }

        /// <summary>
        /// Tests admin-specific functionality.
        /// </summary>
        private static void TestAdminFunctionality()
        {
            Console.WriteLine("--- Admin Functionality Tests ---");

            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test admin identification
            Console.WriteLine("Testing admin identification:");
            TestIsAdmin(authService, "admin", true, "Valid admin user");
            TestIsAdmin(authService, "moderator", false, "Moderator user");
            TestIsAdmin(authService, "regularuser", false, "Regular user");
            TestIsAdmin(authService, "nonexistent", false, "Non-existent user");

            // Test admin dashboard access
            Console.WriteLine("\nTesting admin dashboard access:");
            TestAdminDashboardAccess(authService, "admin", true, "Admin accessing dashboard");
            TestAdminDashboardAccess(authService, "moderator", false, "Moderator accessing dashboard");
            TestAdminDashboardAccess(authService, "regularuser", false, "User accessing dashboard");

            Console.WriteLine();
        }

        /// <summary>
        /// Tests feature access control for different roles.
        /// </summary>
        private static void TestFeatureAccessControl()
        {
            Console.WriteLine("--- Feature Access Control Tests ---");

            var config = SecurityConfiguration.CreateFromEnvironment();
            var logger = new ConsoleSecurityLogger();
            var authService = new AuthenticationService(config, logger);

            // Test moderation tools access
            Console.WriteLine("Testing moderation tools access:");
            TestModerationAccess(authService, "admin", true, "Admin accessing moderation tools");
            TestModerationAccess(authService, "moderator", true, "Moderator accessing moderation tools");
            TestModerationAccess(authService, "regularuser", false, "User accessing moderation tools");

            // Test user creation with roles
            Console.WriteLine("\nTesting user creation with roles:");
            TestUserCreation(authService, "newuser1", "SecurePass123!", "test1@example.com", "user", true, "Creating regular user");
            TestUserCreation(authService, "newmod1", "SecurePass123!", "mod1@example.com", "moderator", true, "Creating moderator");
            TestUserCreation(authService, "newadmin1", "SecurePass123!", "admin1@example.com", "admin", true, "Creating admin");
            TestUserCreation(authService, "invalidrole", "SecurePass123!", "invalid@example.com", "hacker", false, "Creating user with invalid role");

            Console.WriteLine();
        }

        // Helper methods for testing specific scenarios

        private static void TestAuthenticationCase(AuthenticationService authService, string username, string password, bool expected, string description)
        {
            try
            {
                bool result = authService.LoginUser(username, password);
                string status = result == expected ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }

        private static void TestRoleRetrieval(AuthenticationService authService, string username, string? expectedRole, string description)
        {
            try
            {
                string? result = authService.GetUserRole(username);
                bool matches = (result == expectedRole) || (result == null && expectedRole == null);
                string status = matches ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: Expected '{expectedRole}', Got '{result}'");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }

        private static void TestAuthorizationCase(AuthenticationService authService, string username, string requiredRole, bool expected, string description)
        {
            try
            {
                bool result = authService.IsUserAuthorized(username, requiredRole);
                string status = result == expected ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }

        private static void TestPrivilegeEscalation(AuthenticationService authService, string username, string targetRole, bool expected, string description)
        {
            try
            {
                bool result = authService.IsUserAuthorized(username, targetRole);
                string status = result == expected ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }

        private static void TestRoleUpdate(AuthenticationService authService, string adminUser, string targetUser, string newRole, bool expected, string description)
        {
            try
            {
                bool result = authService.UpdateUserRole(adminUser, targetUser, newRole);
                string status = result == expected ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }

        private static void TestIsAdmin(AuthenticationService authService, string username, bool expected, string description)
        {
            try
            {
                bool result = authService.IsAdmin(username);
                string status = result == expected ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }

        private static void TestAdminDashboardAccess(AuthenticationService authService, string username, bool expected, string description)
        {
            try
            {
                bool result = authService.CanAccessAdminDashboard(username);
                string status = result == expected ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }

        private static void TestModerationAccess(AuthenticationService authService, string username, bool expected, string description)
        {
            try
            {
                bool result = authService.CanAccessModerationTools(username);
                string status = result == expected ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }

        private static void TestUserCreation(AuthenticationService authService, string username, string password, string email, string role, bool expected, string description)
        {
            try
            {
                bool result = authService.CreateUser(username, password, email, role);
                string status = result == expected ? "PASS" : "FAIL";
                Console.WriteLine($"  [{status}] {description}: {result}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [ERROR] {description}: Exception - {ex.Message}");
            }
        }
    }
}
