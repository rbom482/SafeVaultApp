using System;

namespace SafeVaultApp.Logging
{
    /// <summary>
    /// Interface for security-focused logging operations.
    /// Provides structured logging for security events and audit trails.
    /// </summary>
    public interface ISecurityLogger
    {
        /// <summary>
        /// Logs authentication attempts with detailed information.
        /// </summary>
        /// <param name="username">Username attempting authentication</param>
        /// <param name="success">Whether authentication was successful</param>
        /// <param name="reason">Reason for failure (if applicable)</param>
        /// <param name="ipAddress">IP address of the client (optional)</param>
        /// <param name="userAgent">User agent string (optional)</param>
        void LogAuthenticationAttempt(string username, bool success, string reason, string? ipAddress = null, string? userAgent = null);

        /// <summary>
        /// Logs security violations and suspicious activities.
        /// </summary>
        /// <param name="violation">Type of security violation</param>
        /// <param name="details">Detailed information about the violation</param>
        /// <param name="username">Username associated with the violation (if applicable)</param>
        /// <param name="ipAddress">IP address of the client (optional)</param>
        void LogSecurityViolation(string violation, string details, string? username = null, string? ipAddress = null);

        /// <summary>
        /// Logs user account actions (creation, lockout, etc.).
        /// </summary>
        /// <param name="action">Type of account action</param>
        /// <param name="username">Username affected</param>
        /// <param name="details">Additional details about the action</param>
        void LogAccountAction(string action, string username, string details);

        /// <summary>
        /// Logs general security events.
        /// </summary>
        /// <param name="eventType">Type of security event</param>
        /// <param name="message">Event message</param>
        /// <param name="severity">Severity level (Info, Warning, Error, Critical)</param>
        void LogSecurityEvent(string eventType, string message, SecurityLogLevel severity = SecurityLogLevel.Info);
    }

    /// <summary>
    /// Security log severity levels.
    /// </summary>
    public enum SecurityLogLevel
    {
        Info,
        Warning,
        Error,
        Critical
    }

    /// <summary>
    /// Basic implementation of ISecurityLogger for demonstration purposes.
    /// In production, consider using a more robust logging framework like Serilog or NLog.
    /// </summary>
    public class ConsoleSecurityLogger : ISecurityLogger
    {
        public void LogAuthenticationAttempt(string username, bool success, string reason, string? ipAddress = null, string? userAgent = null)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");
            var status = success ? "SUCCESS" : "FAILED";
            var ip = !string.IsNullOrEmpty(ipAddress) ? $" from {ipAddress}" : "";
            
            Console.WriteLine($"[{timestamp}] AUTH_{status}: User '{SanitizeForLogging(username)}' {reason}{ip}");
            
            if (!string.IsNullOrEmpty(userAgent))
            {
                Console.WriteLine($"[{timestamp}] AUTH_DETAIL: UserAgent: {SanitizeForLogging(userAgent)}");
            }
        }

        public void LogSecurityViolation(string violation, string details, string? username = null, string? ipAddress = null)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");
            var user = !string.IsNullOrEmpty(username) ? $" User: {SanitizeForLogging(username)}" : "";
            var ip = !string.IsNullOrEmpty(ipAddress) ? $" IP: {ipAddress}" : "";
            
            Console.WriteLine($"[{timestamp}] SECURITY_VIOLATION: {violation} - {SanitizeForLogging(details)}{user}{ip}");
        }

        public void LogAccountAction(string action, string username, string details)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");
            Console.WriteLine($"[{timestamp}] ACCOUNT_{action}: User '{SanitizeForLogging(username)}' - {SanitizeForLogging(details)}");
        }

        public void LogSecurityEvent(string eventType, string message, SecurityLogLevel severity = SecurityLogLevel.Info)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");
            var level = severity.ToString().ToUpper();
            Console.WriteLine($"[{timestamp}] {level}: {eventType} - {SanitizeForLogging(message)}");
        }

        /// <summary>
        /// Sanitizes input for safe logging (prevents log injection attacks).
        /// </summary>
        /// <param name="input">Input to sanitize</param>
        /// <returns>Sanitized string safe for logging</returns>
        private string SanitizeForLogging(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove line breaks and control characters to prevent log injection
            return input.Replace('\r', ' ')
                       .Replace('\n', ' ')
                       .Replace('\t', ' ')
                       .Trim();
        }
    }
}
