using System;

namespace SafeVaultApp.Configuration
{
    /// <summary>
    /// Configuration class for security-related settings.
    /// Provides centralized configuration management following security best practices.
    /// </summary>
    public class SecurityConfiguration
    {
        /// <summary>
        /// Database connection string. Should be retrieved from secure storage in production.
        /// </summary>
        public string ConnectionString { get; set; } = string.Empty;

        /// <summary>
        /// Maximum number of failed login attempts before account lockout.
        /// </summary>
        public int MaxFailedAttempts { get; set; } = 5;

        /// <summary>
        /// Duration in minutes for account lockout after failed attempts.
        /// </summary>
        public int LockoutDurationMinutes { get; set; } = 30;

        /// <summary>
        /// Special characters allowed in passwords.
        /// </summary>
        public string AllowedSpecialCharacters { get; set; } = "!@#$%^&*?";

        /// <summary>
        /// Minimum password length requirement.
        /// </summary>
        public int MinPasswordLength { get; set; } = 8;

        /// <summary>
        /// Number of iterations for PBKDF2 password hashing.
        /// </summary>
        public int HashIterations { get; set; } = 10000;

        /// <summary>
        /// Salt length in bytes for password hashing.
        /// </summary>
        public int SaltLength { get; set; } = 32;

        /// <summary>
        /// Hash length in bytes for password hashing.
        /// </summary>
        public int HashLength { get; set; } = 32;

        /// <summary>
        /// Creates a SecurityConfiguration with values from environment variables or defaults.
        /// </summary>
        /// <returns>Configured SecurityConfiguration instance</returns>
        public static SecurityConfiguration CreateFromEnvironment()
        {
            return new SecurityConfiguration
            {
                ConnectionString = Environment.GetEnvironmentVariable("SAFEVAULT_CONNECTION_STRING") 
                    ?? "Server=localhost;Database=SafeVaultDB;Integrated Security=true;TrustServerCertificate=true;",
                MaxFailedAttempts = int.TryParse(Environment.GetEnvironmentVariable("SAFEVAULT_MAX_FAILED_ATTEMPTS"), out int maxAttempts) 
                    ? maxAttempts : 5,
                LockoutDurationMinutes = int.TryParse(Environment.GetEnvironmentVariable("SAFEVAULT_LOCKOUT_DURATION"), out int lockout) 
                    ? lockout : 30,
                AllowedSpecialCharacters = Environment.GetEnvironmentVariable("SAFEVAULT_ALLOWED_SPECIAL_CHARS") 
                    ?? "!@#$%^&*?",
                MinPasswordLength = int.TryParse(Environment.GetEnvironmentVariable("SAFEVAULT_MIN_PASSWORD_LENGTH"), out int minLength) 
                    ? minLength : 8,
                HashIterations = int.TryParse(Environment.GetEnvironmentVariable("SAFEVAULT_HASH_ITERATIONS"), out int iterations) 
                    ? iterations : 10000,
                SaltLength = int.TryParse(Environment.GetEnvironmentVariable("SAFEVAULT_SALT_LENGTH"), out int saltLength) 
                    ? saltLength : 32,
                HashLength = int.TryParse(Environment.GetEnvironmentVariable("SAFEVAULT_HASH_LENGTH"), out int hashLength) 
                    ? hashLength : 32
            };
        }

        /// <summary>
        /// Validates the configuration settings.
        /// </summary>
        /// <returns>True if configuration is valid</returns>
        public bool IsValid()
        {
            if (string.IsNullOrEmpty(ConnectionString))
                return false;

            if (MaxFailedAttempts <= 0 || MaxFailedAttempts > 20)
                return false;

            if (LockoutDurationMinutes <= 0 || LockoutDurationMinutes > 1440) // Max 24 hours
                return false;

            if (MinPasswordLength < 6 || MinPasswordLength > 128)
                return false;

            if (HashIterations < 1000 || HashIterations > 100000)
                return false;

            if (SaltLength < 16 || SaltLength > 64)
                return false;

            if (HashLength < 16 || HashLength > 64)
                return false;

            return true;
        }
    }
}
