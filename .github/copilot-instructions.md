<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# SafeVault Application - Copilot Instructions

This is a secure coding demonstration project that implements OWASP Top 10 security guidelines. When working with this codebase, please follow these security-focused guidelines:

## Security Principles

1. **Input Validation First**: Always validate and sanitize user input before processing
2. **Parameterized Queries Only**: Never use string concatenation for SQL queries
3. **XSS Protection**: Check for and prevent cross-site scripting in all user inputs
4. **Secure Password Handling**: Use proper hashing (PBKDF2) with cryptographically secure salts
5. **Comprehensive Logging**: Log all security-relevant events for audit purposes

## Code Generation Guidelines

- Always include input validation when creating new methods that accept user input
- Use the existing `ValidationHelpers` class for consistent validation patterns
- Include comprehensive error handling with security-conscious error messages
- Add security-focused unit tests for new functionality
- Follow the existing patterns for parameterized database queries
- Include XML documentation comments explaining security considerations

## Security Testing

- Add test cases that validate against common attack vectors (SQL injection, XSS, etc.)
- Include both positive and negative test cases
- Test edge cases and boundary conditions
- Verify that error handling doesn't leak sensitive information

## Database Operations

- Always use stored procedures or parameterized queries
- Include audit logging for data modifications
- Validate all input parameters at the database level
- Use principle of least privilege for database connections

## Best Practices

- Follow secure coding standards consistently
- Keep security concerns separated and well-documented
- Use defensive programming techniques
- Implement proper exception handling without information disclosure
- Maintain clean, readable code with clear security intentions
