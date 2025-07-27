using System;
using System.Linq;
using Microsoft.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using SafeVaultApp.Helpers;
using SafeVaultApp.Configuration;
using SafeVaultApp.Logging;

namespace SafeVaultApp.Services
{
    /// <summary>
    /// Provides secure authentication services with protection against SQL injection
    /// and other security vulnerabilities. Follows OWASP Top 10 guidelines.
    /// </summary>
    public class AuthenticationService
    {
        private readonly SecurityConfiguration _config;
        private readonly ISecurityLogger _logger;

        /// <summary>
        /// Initializes a new instance of the AuthenticationService.
        /// </summary>
        /// <param name="config">Security configuration settings</param>
        /// <param name="logger">Security logger for audit trails</param>
        public AuthenticationService(SecurityConfiguration config, ISecurityLogger logger)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            if (!_config.IsValid())
            {
                throw new ArgumentException("Invalid security configuration", nameof(config));
            }
        }

        /// <summary>
        /// Legacy constructor for backward compatibility.
        /// </summary>
        /// <param name="connectionString">Database connection string</param>
        [Obsolete("Use constructor with SecurityConfiguration and ISecurityLogger instead")]
        public AuthenticationService(string connectionString)
        {
            _config = new SecurityConfiguration { ConnectionString = connectionString };
            _logger = new ConsoleSecurityLogger();
        }

        /// <summary>
        /// Securely authenticates a user using parameterized queries to prevent SQL injection.
        /// Validates input before processing and uses secure password comparison.
        /// </summary>
        /// <param name="username">Username to authenticate</param>
        /// <param name="password">Password to verify</param>
        /// <returns>True if authentication successful, false otherwise</returns>
        public bool LoginUser(string username, string password)
        {
            // Validate inputs using ValidationHelpers to prevent injection attacks
            if (!ValidationHelpers.IsValidInput(username) || 
                !ValidationHelpers.IsValidInput(password, _config.AllowedSpecialCharacters))
            {
                _logger.LogAuthenticationAttempt(username, false, "Invalid input format");
                return false;
            }

            // Additional XSS validation
            if (!ValidationHelpers.IsValidXSSInput(username) || 
                !ValidationHelpers.IsValidXSSInput(password))
            {
                _logger.LogSecurityViolation("XSS_ATTEMPT", "Potential XSS attempt in authentication", username);
                return false;
            }

            try
            {
                // Use parameterized query to prevent SQL injection
                string query = "SELECT PasswordHash, Salt FROM Users WHERE Username = @Username AND IsActive = 1";

                using (var connection = new SqlConnection(_config.ConnectionString))
                {
                    using (var command = new SqlCommand(query, connection))
                    {
                        // Use parameters to prevent SQL injection
                        command.Parameters.AddWithValue("@Username", username);

                        connection.Open();

                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string? storedHash = reader["PasswordHash"]?.ToString();
                                string? salt = reader["Salt"]?.ToString();

                                // Ensure we have valid hash and salt before verification
                                if (!string.IsNullOrEmpty(storedHash) && !string.IsNullOrEmpty(salt))
                                {
                                    bool isValid = VerifyPassword(password, storedHash, salt);
                                    _logger.LogAuthenticationAttempt(username, isValid, 
                                        isValid ? "Authentication successful" : "Invalid credentials");
                                    return isValid;
                                }
                                else
                                {
                                    _logger.LogSecurityViolation("DATA_INTEGRITY", "Null password hash or salt in database", username);
                                }
                            }
                            else
                            {
                                _logger.LogAuthenticationAttempt(username, false, "User not found");
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                _logger.LogSecurityEvent("DATABASE_ERROR", $"Database error during authentication: {ex.Message}", SecurityLogLevel.Error);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogSecurityEvent("UNEXPECTED_ERROR", $"Unexpected error during authentication: {ex.Message}", SecurityLogLevel.Error);
                return false;
            }

            return false;
        }

        /// <summary>
        /// Securely retrieves user data using parameterized queries.
        /// Example of how to fetch data safely to prevent SQL injection.
        /// </summary>
        /// <param name="userId">User ID to fetch data for</param>
        /// <returns>User data or null if not found</returns>
        public UserData? GetUserData(int userId)
        {
            // Validate userId (basic validation for positive integer)
            if (userId <= 0)
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid user ID provided", null);
                return null;
            }

            try
            {
                // Parameterized query prevents SQL injection
                string query = @"
                    SELECT UserId, Username, Email, FirstName, LastName, CreatedDate, LastLoginDate, UserRole 
                    FROM Users 
                    WHERE UserId = @UserId AND IsActive = 1";

                using (var connection = new SqlConnection(_config.ConnectionString))
                {
                    using (var command = new SqlCommand(query, connection))
                    {
                        // Use parameter to prevent SQL injection
                        command.Parameters.AddWithValue("@UserId", userId);

                        connection.Open();

                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                return new UserData
                                {
                                    UserId = (int)reader["UserId"],
                                    Username = reader["Username"]?.ToString() ?? string.Empty,
                                    Email = reader["Email"]?.ToString() ?? string.Empty,
                                    FirstName = reader["FirstName"]?.ToString(),
                                    LastName = reader["LastName"]?.ToString(),
                                    CreatedDate = (DateTime)reader["CreatedDate"],
                                    LastLoginDate = reader["LastLoginDate"] as DateTime?,
                                    UserRole = reader["UserRole"]?.ToString() ?? "user"
                                };
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                _logger.LogSecurityEvent("DATABASE_ERROR", $"Database error fetching user data: {ex.Message}", SecurityLogLevel.Error);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogSecurityEvent("UNEXPECTED_ERROR", $"Unexpected error fetching user data: {ex.Message}", SecurityLogLevel.Error);
                return null;
            }

            return null;
        }

        /// <summary>
        /// Creates a new user with secure password hashing.
        /// Demonstrates secure user creation with proper input validation.
        /// </summary>
        /// <param name="username">Username for new user</param>
        /// <param name="password">Password for new user</param>
        /// <param name="email">Email for new user</param>
        /// <param name="role">User role (defaults to 'user')</param>
        /// <returns>True if user created successfully</returns>
        public bool CreateUser(string username, string password, string email, string role = "user")
        {
            // Comprehensive input validation
            if (!ValidationHelpers.IsValidInput(username) ||
                !ValidationHelpers.IsValidPassword(password, _config.MinPasswordLength) ||
                !ValidationHelpers.IsValidEmail(email) ||
                !ValidationHelpers.IsValidInput(role))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid input during user creation", username);
                return false;
            }

            // XSS validation
            if (!ValidationHelpers.IsValidXSSInput(username) ||
                !ValidationHelpers.IsValidXSSInput(email) ||
                !ValidationHelpers.IsValidXSSInput(role))
            {
                _logger.LogSecurityViolation("XSS_ATTEMPT", "Potential XSS attempt during user creation", username);
                return false;
            }

            // Validate role is in allowed values
            string[] allowedRoles = { "user", "admin", "moderator" };
            if (!allowedRoles.Contains(role.ToLower()))
            {
                _logger.LogSecurityViolation("INVALID_ROLE", $"Invalid role '{role}' during user creation", username);
                return false;
            }

            try
            {
                // Generate salt and hash password securely
                string salt = GenerateSalt();
                string passwordHash = HashPassword(password, salt);

                // Parameterized query to prevent SQL injection
                string query = @"
                    INSERT INTO Users (Username, PasswordHash, Salt, Email, CreatedDate, IsActive, UserRole)
                    VALUES (@Username, @PasswordHash, @Salt, @Email, @CreatedDate, 1, @UserRole)";

                using (var connection = new SqlConnection(_config.ConnectionString))
                {
                    using (var command = new SqlCommand(query, connection))
                    {
                        // Use parameters to prevent SQL injection
                        command.Parameters.AddWithValue("@Username", username);
                        command.Parameters.AddWithValue("@PasswordHash", passwordHash);
                        command.Parameters.AddWithValue("@Salt", salt);
                        command.Parameters.AddWithValue("@Email", email);
                        command.Parameters.AddWithValue("@CreatedDate", DateTime.UtcNow);
                        command.Parameters.AddWithValue("@UserRole", role);

                        connection.Open();
                        int rowsAffected = command.ExecuteNonQuery();

                        bool success = rowsAffected > 0;
                        if (success)
                        {
                            _logger.LogAccountAction("CREATED", username, "User account created successfully");
                        }
                        return success;
                    }
                }
            }
            catch (SqlException ex)
            {
                _logger.LogSecurityEvent("DATABASE_ERROR", $"Database error creating user: {ex.Message}", SecurityLogLevel.Error);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogSecurityEvent("UNEXPECTED_ERROR", $"Unexpected error creating user: {ex.Message}", SecurityLogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Securely verifies a password against its hash using PBKDF2.
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <param name="hash">Stored password hash</param>
        /// <param name="salt">Password salt</param>
        /// <returns>True if password matches</returns>
        private bool VerifyPassword(string password, string hash, string salt)
        {
            string hashedPassword = HashPassword(password, salt);
            return string.Equals(hash, hashedPassword, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Securely hashes a password using PBKDF2 with SHA256.
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <param name="salt">Password salt</param>
        /// <returns>Hashed password</returns>
        private string HashPassword(string password, string salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(salt), _config.HashIterations, HashAlgorithmName.SHA256))
            {
                byte[] hash = pbkdf2.GetBytes(_config.HashLength);
                return Convert.ToBase64String(hash);
            }
        }

        /// <summary>
        /// Generates a cryptographically secure random salt.
        /// </summary>
        /// <returns>Base64 encoded salt</returns>
        private string GenerateSalt()
        {
            byte[] salt = new byte[_config.SaltLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return Convert.ToBase64String(salt);
        }

        /// <summary>
        /// Checks if a user has the required role for authorization.
        /// This method implements role-based access control (RBAC).
        /// </summary>
        /// <param name="username">Username to check authorization for</param>
        /// <param name="requiredRole">Required role for the operation</param>
        /// <returns>True if user is authorized, false otherwise</returns>
        public bool IsUserAuthorized(string username, string requiredRole)
        {
            // Validate inputs
            if (!ValidationHelpers.IsValidInput(username) || !ValidationHelpers.IsValidInput(requiredRole))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid input during authorization check", username);
                return false;
            }

            // XSS validation
            if (!ValidationHelpers.IsValidXSSInput(username) || !ValidationHelpers.IsValidXSSInput(requiredRole))
            {
                _logger.LogSecurityViolation("XSS_ATTEMPT", "Potential XSS attempt during authorization", username);
                return false;
            }

            try
            {
                using (var connection = new SqlConnection(_config.ConnectionString))
                {
                    using (var command = new SqlCommand("sp_CheckUserRole", connection))
                    {
                        command.CommandType = System.Data.CommandType.StoredProcedure;
                        command.Parameters.AddWithValue("@Username", username);
                        command.Parameters.AddWithValue("@RequiredRole", requiredRole);

                        connection.Open();

                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string? status = reader["Status"]?.ToString();
                                string? userRole = reader["UserRole"]?.ToString();

                                bool isAuthorized = status == "AUTHORIZED";
                                
                                _logger.LogSecurityEvent("AUTHORIZATION_CHECK", 
                                    $"User '{username}' authorization check for role '{requiredRole}': {status} (Current role: {userRole})", 
                                    isAuthorized ? SecurityLogLevel.Info : SecurityLogLevel.Warning);

                                return isAuthorized;
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                _logger.LogSecurityEvent("DATABASE_ERROR", $"Database error during authorization check: {ex.Message}", SecurityLogLevel.Error);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogSecurityEvent("UNEXPECTED_ERROR", $"Unexpected error during authorization check: {ex.Message}", SecurityLogLevel.Error);
                return false;
            }

            return false;
        }

        /// <summary>
        /// Gets the role of a user.
        /// Used for role-based authorization decisions.
        /// </summary>
        /// <param name="username">Username to get role for</param>
        /// <returns>User role or null if user not found</returns>
        public string? GetUserRole(string username)
        {
            // Validate input
            if (!ValidationHelpers.IsValidInput(username))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid username during role retrieval", username);
                return null;
            }

            // XSS validation
            if (!ValidationHelpers.IsValidXSSInput(username))
            {
                _logger.LogSecurityViolation("XSS_ATTEMPT", "Potential XSS attempt during role retrieval", username);
                return null;
            }

            try
            {
                string query = "SELECT UserRole FROM Users WHERE Username = @Username AND IsActive = 1";

                using (var connection = new SqlConnection(_config.ConnectionString))
                {
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@Username", username);

                        connection.Open();

                        object? result = command.ExecuteScalar();
                        string? role = result?.ToString();

                        _logger.LogSecurityEvent("ROLE_RETRIEVAL", 
                            $"Retrieved role for user '{username}': {role ?? "NOT_FOUND"}", 
                            SecurityLogLevel.Info);

                        return role;
                    }
                }
            }
            catch (SqlException ex)
            {
                _logger.LogSecurityEvent("DATABASE_ERROR", $"Database error retrieving user role: {ex.Message}", SecurityLogLevel.Error);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogSecurityEvent("UNEXPECTED_ERROR", $"Unexpected error retrieving user role: {ex.Message}", SecurityLogLevel.Error);
                return null;
            }
        }

        /// <summary>
        /// Updates a user's role (admin only operation).
        /// Demonstrates secure role management with proper authorization.
        /// </summary>
        /// <param name="adminUsername">Username of the admin performing the operation</param>
        /// <param name="targetUsername">Username of the user whose role is being changed</param>
        /// <param name="newRole">New role to assign</param>
        /// <param name="ipAddress">IP address for audit logging</param>
        /// <returns>True if role updated successfully</returns>
        public bool UpdateUserRole(string adminUsername, string targetUsername, string newRole, string? ipAddress = null)
        {
            // Validate all inputs
            if (!ValidationHelpers.IsValidInput(adminUsername) || 
                !ValidationHelpers.IsValidInput(targetUsername) || 
                !ValidationHelpers.IsValidInput(newRole))
            {
                _logger.LogSecurityViolation("INVALID_INPUT", "Invalid input during role update", adminUsername);
                return false;
            }

            // XSS validation
            if (!ValidationHelpers.IsValidXSSInput(adminUsername) || 
                !ValidationHelpers.IsValidXSSInput(targetUsername) || 
                !ValidationHelpers.IsValidXSSInput(newRole))
            {
                _logger.LogSecurityViolation("XSS_ATTEMPT", "Potential XSS attempt during role update", adminUsername);
                return false;
            }

            // Validate role is in allowed values
            string[] allowedRoles = { "user", "admin", "moderator" };
            if (!allowedRoles.Contains(newRole.ToLower()))
            {
                _logger.LogSecurityViolation("INVALID_ROLE", $"Invalid role '{newRole}' attempted", adminUsername);
                return false;
            }

            try
            {
                using (var connection = new SqlConnection(_config.ConnectionString))
                {
                    using (var command = new SqlCommand("sp_UpdateUserRole", connection))
                    {
                        command.CommandType = System.Data.CommandType.StoredProcedure;
                        command.Parameters.AddWithValue("@AdminUsername", adminUsername);
                        command.Parameters.AddWithValue("@TargetUsername", targetUsername);
                        command.Parameters.AddWithValue("@NewRole", newRole);
                        command.Parameters.AddWithValue("@IPAddress", ipAddress ?? (object)DBNull.Value);

                        connection.Open();

                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string? status = reader["Status"]?.ToString();
                                bool success = status == "SUCCESS";

                                _logger.LogSecurityEvent("ROLE_UPDATE", 
                                    $"Role update attempt by '{adminUsername}' for user '{targetUsername}' to role '{newRole}': {status}", 
                                    success ? SecurityLogLevel.Info : SecurityLogLevel.Warning);

                                return success;
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                _logger.LogSecurityEvent("DATABASE_ERROR", $"Database error during role update: {ex.Message}", SecurityLogLevel.Error);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogSecurityEvent("UNEXPECTED_ERROR", $"Unexpected error during role update: {ex.Message}", SecurityLogLevel.Error);
                return false;
            }

            return false;
        }

        /// <summary>
        /// Checks if a user has admin privileges.
        /// Convenience method for admin-only operations.
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <returns>True if user is an admin</returns>
        public bool IsAdmin(string username)
        {
            return IsUserAuthorized(username, "admin");
        }

        /// <summary>
        /// Demonstrates secure feature access control.
        /// Example of protecting an admin dashboard.
        /// </summary>
        /// <param name="username">Username attempting to access the feature</param>
        /// <returns>True if access is granted</returns>
        public bool CanAccessAdminDashboard(string username)
        {
            bool hasAccess = IsUserAuthorized(username, "admin");
            
            _logger.LogSecurityEvent("ADMIN_DASHBOARD_ACCESS", 
                $"Admin dashboard access attempt by user '{username}': {(hasAccess ? "GRANTED" : "DENIED")}", 
                hasAccess ? SecurityLogLevel.Info : SecurityLogLevel.Warning);

            return hasAccess;
        }

        /// <summary>
        /// Demonstrates role-based feature access.
        /// Example of protecting a moderator feature.
        /// </summary>
        /// <param name="username">Username attempting to access the feature</param>
        /// <returns>True if access is granted</returns>
        public bool CanAccessModerationTools(string username)
        {
            // Moderators and admins can access moderation tools
            bool hasAccess = IsUserAuthorized(username, "moderator");
            
            _logger.LogSecurityEvent("MODERATION_TOOLS_ACCESS", 
                $"Moderation tools access attempt by user '{username}': {(hasAccess ? "GRANTED" : "DENIED")}", 
                hasAccess ? SecurityLogLevel.Info : SecurityLogLevel.Warning);

            return hasAccess;
        }
    }

    /// <summary>
    /// Represents user data retrieved from the database.
    /// </summary>
    public class UserData
    {
        public int UserId { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public string UserRole { get; set; } = "user";
    }

    /// <summary>
    /// Enumeration of available user roles for role-based authorization.
    /// </summary>
    public enum UserRole
    {
        User,
        Moderator,
        Admin
    }
}
