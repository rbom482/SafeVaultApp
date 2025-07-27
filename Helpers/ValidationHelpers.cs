using System;
using System.Linq;
using System.Collections.Generic;

namespace SafeVaultApp.Helpers
{
    /// <summary>
    /// Provides secure input validation methods to prevent security vulnerabilities.
    /// Follows OWASP Top 10 guidelines for input validation.
    /// </summary>
    public static class ValidationHelpers
    {
        /// <summary>
        /// Validates user input by checking if it contains only allowed characters.
        /// This method helps prevent injection attacks by restricting input to safe characters.
        /// </summary>
        /// <param name="input">The input string to validate</param>
        /// <param name="allowedSpecialCharacters">String containing allowed special characters</param>
        /// <returns>True if input is valid, false otherwise</returns>
        public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
        {
            // Reject null or empty input as invalid
            if (string.IsNullOrEmpty(input))
                return false;

            // Convert allowed special characters to a HashSet for efficient lookup
            var validCharacters = allowedSpecialCharacters.ToHashSet();

            // Check each character - must be letter, digit, or in allowed special characters
            return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
        }

        /// <summary>
        /// Validates input against XSS (Cross-Site Scripting) attacks.
        /// Checks for potentially malicious script tags and iframe elements.
        /// </summary>
        /// <param name="input">The input string to validate for XSS</param>
        /// <returns>True if input is safe from XSS, false if potentially malicious</returns>
        public static bool IsValidXSSInput(string input)
        {
            // Allow null or empty input
            if (string.IsNullOrEmpty(input))
                return true;

            // Convert to lowercase for case-insensitive checking
            string lowerInput = input.ToLower();

            // Check for dangerous script tags and iframe elements
            if (lowerInput.Contains("<script") || lowerInput.Contains("<iframe"))
                return false;

            // Additional XSS protection - check for other dangerous elements
            string[] dangerousPatterns = {
                "<object", "<embed", "<applet", "<meta", "<link",
                "javascript:", "vbscript:", "onload=", "onerror=",
                "onclick=", "onmouseover=", "onfocus=", "onblur=",
                "expression(", "eval(", "setTimeout(", "setInterval(",
                "data:", "livescript:", "mocha:"
            };

            foreach (string pattern in dangerousPatterns)
            {
                if (lowerInput.Contains(pattern))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Sanitizes input by removing potentially dangerous characters and patterns.
        /// Use this method when you need to clean input rather than reject it entirely.
        /// </summary>
        /// <param name="input">The input string to sanitize</param>
        /// <returns>Sanitized input string</returns>
        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove HTML tags and dangerous patterns
            string sanitized = input;

            // Remove script tags and their content
            sanitized = System.Text.RegularExpressions.Regex.Replace(
                sanitized, @"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", 
                "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            // Remove other dangerous HTML elements
            string[] dangerousTags = { "script", "iframe", "object", "embed", "applet", "meta", "link" };
            foreach (string tag in dangerousTags)
            {
                sanitized = System.Text.RegularExpressions.Regex.Replace(
                    sanitized, $@"<\s*{tag}\b[^>]*>.*?<\s*/\s*{tag}\s*>", 
                    "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }

            // Remove event handlers
            sanitized = System.Text.RegularExpressions.Regex.Replace(
                sanitized, @"\s*on\w+\s*=\s*[""'][^""']*[""']", 
                "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            return sanitized.Trim();
        }

        /// <summary>
        /// Validates email format using a secure pattern.
        /// </summary>
        /// <param name="email">Email address to validate</param>
        /// <returns>True if email format is valid</returns>
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return false;

            // Basic email validation pattern - you might want to use a more sophisticated library
            // for production applications
            return System.Text.RegularExpressions.Regex.IsMatch(email,
                @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
        }

        /// <summary>
        /// Validates that a string meets minimum security requirements for passwords.
        /// </summary>
        /// <param name="password">Password to validate</param>
        /// <param name="minLength">Minimum required length</param>
        /// <returns>True if password meets security requirements</returns>
        public static bool IsValidPassword(string password, int minLength = 8)
        {
            if (string.IsNullOrEmpty(password) || password.Length < minLength)
                return false;

            // Check for required character types
            bool hasLower = password.Any(char.IsLower);
            bool hasUpper = password.Any(char.IsUpper);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSpecial = password.Any(c => "!@#$%^&*()_+-=[]{}|;:,.<>?".Contains(c));

            return hasLower && hasUpper && hasDigit && hasSpecial;
        }
    }
}
