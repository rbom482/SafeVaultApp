using System;
using System.Collections.Generic;
using SafeVaultApp.Services;
using SafeVaultApp.Configuration;
using SafeVaultApp.Logging;
using SafeVaultApp.Helpers;

namespace SafeVaultApp.Features
{
    /// <summary>
    /// Demonstrates secure admin dashboard functionality with role-based authorization.
    /// Only users with admin role can access administrative features.
    /// Implements OWASP security guidelines for administrative interfaces.
    /// </summary>
    public class AdminDashboard
    {
        private readonly AuthenticationService _authService;
        private readonly ISecurityLogger _logger;

        /// <summary>
        /// Initializes the admin dashboard with required services.
        /// </summary>
        public AdminDashboard(AuthenticationService authService, ISecurityLogger logger)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Main entry point for admin dashboard access.
        /// Verifies admin privileges before granting access.
        /// </summary>
        /// <param name="username">Username attempting to access dashboard</param>
        /// <returns>True if access granted and dashboard shown</returns>
        public bool AccessDashboard(string username)
        {
            // Validate input
            if (!ValidationHelpers.IsValidInput(username))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid username format for admin dashboard access", username);
                return false;
            }

            // Check admin authorization
            if (!_authService.CanAccessAdminDashboard(username))
            {
                _logger.LogSecurityViolation("UNAUTHORIZED_ACCESS", "Unauthorized admin dashboard access attempt", username);
                Console.WriteLine("❌ Access Denied: Admin privileges required.");
                return false;
            }

            // Grant access and show dashboard
            ShowAdminDashboard(username);
            return true;
        }

        /// <summary>
        /// Displays the admin dashboard interface.
        /// </summary>
        private void ShowAdminDashboard(string adminUsername)
        {
            Console.WriteLine("\n🛡️  === SafeVault Admin Dashboard ===");
            Console.WriteLine($"Welcome, Administrator: {adminUsername}");
            Console.WriteLine($"Access granted at: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            
            Console.WriteLine("\nAvailable Admin Functions:");
            Console.WriteLine("1. 👥 User Management");
            Console.WriteLine("2. 🔐 Security Monitoring");
            Console.WriteLine("3. 📊 System Statistics");
            Console.WriteLine("4. 🔧 Configuration Management");
            Console.WriteLine("5. 📋 Audit Logs");

            _logger.LogSecurityEvent("ADMIN_DASHBOARD_ACCESS", 
                $"Admin dashboard accessed by '{adminUsername}'", 
                SecurityLogLevel.Info);
        }

        /// <summary>
        /// Manages user accounts - admin only feature.
        /// </summary>
        public bool ManageUsers(string adminUsername)
        {
            if (!_authService.IsAdmin(adminUsername))
            {
                _logger.LogSecurityViolation("UNAUTHORIZED_ADMIN_ACTION", "Non-admin attempted user management", adminUsername);
                Console.WriteLine("❌ Access Denied: Admin privileges required for user management.");
                return false;
            }

            Console.WriteLine("\n👥 === User Management ===");
            Console.WriteLine("Available actions:");
            Console.WriteLine("• Create new user accounts");
            Console.WriteLine("• Modify user roles");
            Console.WriteLine("• Deactivate/activate accounts");
            Console.WriteLine("• Reset account lockouts");

            _logger.LogSecurityEvent("USER_MANAGEMENT_ACCESS", 
                $"User management accessed by admin '{adminUsername}'", 
                SecurityLogLevel.Info);

            return true;
        }

        /// <summary>
        /// Demonstrates role assignment functionality.
        /// </summary>
        public bool AssignUserRole(string adminUsername, string targetUsername, string newRole)
        {
            // Verify admin privileges
            if (!_authService.IsAdmin(adminUsername))
            {
                _logger.LogSecurityViolation("UNAUTHORIZED_ROLE_ASSIGNMENT", "Non-admin attempted role assignment", adminUsername);
                Console.WriteLine("❌ Access Denied: Only administrators can assign roles.");
                return false;
            }

            // Validate inputs
            if (!ValidationHelpers.IsValidInput(targetUsername) || !ValidationHelpers.IsValidInput(newRole))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid input during role assignment", adminUsername);
                Console.WriteLine("❌ Error: Invalid input provided.");
                return false;
            }

            // Perform role assignment
            bool success = _authService.UpdateUserRole(adminUsername, targetUsername, newRole);
            
            if (success)
            {
                Console.WriteLine($"✅ Successfully assigned role '{newRole}' to user '{targetUsername}'");
                _logger.LogSecurityEvent("ROLE_ASSIGNED", 
                    $"Admin '{adminUsername}' assigned role '{newRole}' to user '{targetUsername}'", 
                    SecurityLogLevel.Info);
            }
            else
            {
                Console.WriteLine($"❌ Failed to assign role '{newRole}' to user '{targetUsername}'");
                _logger.LogSecurityEvent("ROLE_ASSIGNMENT_FAILED", 
                    $"Admin '{adminUsername}' failed to assign role '{newRole}' to user '{targetUsername}'", 
                    SecurityLogLevel.Warning);
            }

            return success;
        }

        /// <summary>
        /// Views security monitoring dashboard - admin only.
        /// </summary>
        public bool ViewSecurityMonitoring(string adminUsername)
        {
            if (!_authService.IsAdmin(adminUsername))
            {
                _logger.LogSecurityViolation("UNAUTHORIZED_SECURITY_ACCESS", "Non-admin attempted security monitoring access", adminUsername);
                Console.WriteLine("❌ Access Denied: Admin privileges required for security monitoring.");
                return false;
            }

            Console.WriteLine("\n🔐 === Security Monitoring ===");
            Console.WriteLine("Recent Security Events:");
            Console.WriteLine($"• {DateTime.UtcNow.AddMinutes(-10):HH:mm:ss} - Failed login attempt from unknown user");
            Console.WriteLine($"• {DateTime.UtcNow.AddMinutes(-25):HH:mm:ss} - XSS attempt blocked in user input");
            Console.WriteLine($"• {DateTime.UtcNow.AddMinutes(-45):HH:mm:ss} - SQL injection attempt prevented");
            Console.WriteLine($"• {DateTime.UtcNow.AddHours(-1):HH:mm:ss} - Account lockout triggered for excessive failed attempts");

            Console.WriteLine("\nSecurity Statistics:");
            Console.WriteLine("• Active Users: 245");
            Console.WriteLine("• Failed Login Attempts (24h): 12");
            Console.WriteLine("• Blocked Attack Attempts (24h): 5");
            Console.WriteLine("• Admin Actions (24h): 3");

            _logger.LogSecurityEvent("SECURITY_MONITORING_ACCESS", 
                $"Security monitoring accessed by admin '{adminUsername}'", 
                SecurityLogLevel.Info);

            return true;
        }
    }

    /// <summary>
    /// Demonstrates secure moderation tools with role-based authorization.
    /// Accessible by both moderators and administrators.
    /// </summary>
    public class ModerationTools
    {
        private readonly AuthenticationService _authService;
        private readonly ISecurityLogger _logger;

        public ModerationTools(AuthenticationService authService, ISecurityLogger logger)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Access moderation tools interface.
        /// </summary>
        public bool AccessModerationTools(string username)
        {
            // Validate input
            if (!ValidationHelpers.IsValidInput(username))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid username for moderation access", username);
                return false;
            }

            // Check authorization (moderator or admin)
            if (!_authService.CanAccessModerationTools(username))
            {
                _logger.LogSecurityViolation("UNAUTHORIZED_MODERATION_ACCESS", "Unauthorized moderation tools access", username);
                Console.WriteLine("❌ Access Denied: Moderator or Admin privileges required.");
                return false;
            }

            ShowModerationInterface(username);
            return true;
        }

        /// <summary>
        /// Displays moderation tools interface.
        /// </summary>
        private void ShowModerationInterface(string username)
        {
            string userRole = _authService.GetUserRole(username) ?? "unknown";
            
            Console.WriteLine("\n🛠️  === SafeVault Moderation Tools ===");
            Console.WriteLine($"Welcome, {userRole.ToUpper()}: {username}");
            
            Console.WriteLine("\nAvailable Moderation Functions:");
            Console.WriteLine("1. 📝 Content Moderation");
            Console.WriteLine("2. 👤 User Warnings");
            Console.WriteLine("3. 🚫 Temporary Suspensions");
            Console.WriteLine("4. 📊 Moderation Reports");
            
            if (_authService.IsAdmin(username))
            {
                Console.WriteLine("5. 🔧 Advanced Admin Tools (Admin Only)");
            }

            _logger.LogSecurityEvent("MODERATION_TOOLS_ACCESS", 
                $"Moderation tools accessed by {userRole} '{username}'", 
                SecurityLogLevel.Info);
        }

        /// <summary>
        /// Moderate content - available to moderators and admins.
        /// </summary>
        public bool ModerateContent(string username, string contentId, string action)
        {
            if (!_authService.CanAccessModerationTools(username))
            {
                _logger.LogSecurityViolation("UNAUTHORIZED_MODERATION_ACTION", "Unauthorized content moderation attempt", username);
                Console.WriteLine("❌ Access Denied: Moderation privileges required.");
                return false;
            }

            // Validate inputs
            if (!ValidationHelpers.IsValidInput(contentId) || !ValidationHelpers.IsValidInput(action))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid input during content moderation", username);
                return false;
            }

            Console.WriteLine($"✅ Content {contentId} has been {action} by moderator {username}");
            
            _logger.LogSecurityEvent("CONTENT_MODERATED", 
                $"Content '{contentId}' {action} by {_authService.GetUserRole(username)} '{username}'", 
                SecurityLogLevel.Info);

            return true;
        }
    }

    /// <summary>
    /// Demonstrates user-level features that all authenticated users can access.
    /// </summary>
    public class UserFeatures
    {
        private readonly AuthenticationService _authService;
        private readonly ISecurityLogger _logger;

        public UserFeatures(AuthenticationService authService, ISecurityLogger logger)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Access user dashboard - available to all authenticated users.
        /// </summary>
        public bool AccessUserDashboard(string username)
        {
            // Validate input
            if (!ValidationHelpers.IsValidInput(username))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid username for user dashboard", username);
                return false;
            }

            // Check if user exists and is active (basic authorization)
            string? userRole = _authService.GetUserRole(username);
            if (userRole == null)
            {
                _logger.LogSecurityViolation("UNAUTHORIZED_ACCESS", "Non-existent user attempted dashboard access", username);
                Console.WriteLine("❌ Access Denied: User not found or inactive.");
                return false;
            }

            ShowUserDashboard(username, userRole);
            return true;
        }

        /// <summary>
        /// Displays user dashboard based on role.
        /// </summary>
        private void ShowUserDashboard(string username, string role)
        {
            Console.WriteLine("\n👤 === SafeVault User Dashboard ===");
            Console.WriteLine($"Welcome, {username} ({role.ToUpper()})");
            
            Console.WriteLine("\nAvailable Features:");
            Console.WriteLine("1. 📁 My Files");
            Console.WriteLine("2. ⚙️  Account Settings");
            Console.WriteLine("3. 🔒 Security Settings");
            
            // Show additional options based on role
            if (role == "moderator" || role == "admin")
            {
                Console.WriteLine("4. 🛠️  Moderation Tools");
            }
            
            if (role == "admin")
            {
                Console.WriteLine("5. 🛡️  Admin Dashboard");
            }

            _logger.LogSecurityEvent("USER_DASHBOARD_ACCESS", 
                $"User dashboard accessed by {role} '{username}'", 
                SecurityLogLevel.Info);
        }

        /// <summary>
        /// View account information - user-level feature.
        /// </summary>
        public bool ViewAccountInfo(string username)
        {
            if (string.IsNullOrEmpty(username) || !ValidationHelpers.IsValidInput(username))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid username for account info access", username);
                return false;
            }

            UserData? userData = _authService.GetUserData(GetUserIdByUsername(username));
            if (userData == null)
            {
                Console.WriteLine("❌ Error: Unable to retrieve account information.");
                return false;
            }

            Console.WriteLine("\n📋 === Account Information ===");
            Console.WriteLine($"Username: {userData.Username}");
            Console.WriteLine($"Email: {userData.Email}");
            Console.WriteLine($"Role: {userData.UserRole}");
            Console.WriteLine($"Created: {userData.CreatedDate:yyyy-MM-dd}");
            Console.WriteLine($"Last Login: {userData.LastLoginDate?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");

            _logger.LogSecurityEvent("ACCOUNT_INFO_VIEW", 
                $"Account information viewed by user '{username}'", 
                SecurityLogLevel.Info);

            return true;
        }

        /// <summary>
        /// Helper method to get user ID by username (simplified for demo).
        /// In production, this would be properly implemented with database queries.
        /// </summary>
        private int GetUserIdByUsername(string username)
        {
            // This is a simplified implementation for demonstration
            // In production, you would query the database to get the actual user ID
            return username.GetHashCode() & 0x7FFFFFFF; // Simple hash for demo
        }
    }
}
