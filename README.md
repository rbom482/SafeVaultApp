# SafeVault Application - Enhanced Security Implementation

A comprehensive demonstration of secure coding principles using Microsoft Copilot, implementing protection against common vulnerabilities such as SQL injection and XSS attacks while following OWASP Top 10 guidelines.

## 🆕 **RECENT IMPROVEMENTS**

### **✅ Technical Upgrades**
- **Modern SQL Client**: Upgraded from deprecated `System.Data.SqlClient` to `Microsoft.Data.SqlClient`
- **Nullable Reference Types**: Fixed all nullable reference type warnings for better type safety
- **Configuration Management**: Centralized security configuration with environment variable support
- **Structured Logging**: Implemented comprehensive security logging with audit trails

### **🔐 Enhanced Security Features**
- **Advanced XSS Protection**: Extended pattern detection for `expression()`, `eval()`, `setTimeout()`, etc.
- **Security Configuration**: Configurable security parameters (hash iterations, salt length, lockout duration)
- **Audit Logging**: Detailed security event logging with timestamps and severity levels
- **Input Sanitization**: Enhanced log injection prevention and content sanitization

## 🔒 Security Features

### 1. Input Validation
- **Character-level validation**: Only allows alphanumeric characters and specified special characters
- **XSS protection**: Detects and blocks cross-site scripting attempts
- **SQL injection prevention**: Validates input before database operations
- **Email validation**: Ensures proper email format
- **Password strength validation**: Enforces strong password requirements

### 2. Secure Authentication
- **Parameterized queries**: All database operations use parameterized queries to prevent SQL injection
- **Password hashing**: Uses PBKDF2 with SHA-256 for secure password storage
- **Salt generation**: Cryptographically secure random salt for each password
- **Account lockout**: Prevents brute force attacks with automatic account locking
- **Session management**: Secure session handling with proper expiration

### 3. XSS Protection
- **Script tag detection**: Blocks `<script>` and `<iframe>` tags
- **Event handler blocking**: Prevents JavaScript event handlers in input
- **Input sanitization**: Removes dangerous HTML elements and attributes
- **Content validation**: Comprehensive checking for malicious patterns

### 4. Database Security
- **Stored procedures**: Secure data access through parameterized stored procedures
- **Audit logging**: Comprehensive logging of all security-relevant events
- **Minimal permissions**: Database schema designed with principle of least privilege
- **Secure views**: Safe data access that excludes sensitive information

## 🏗️ Project Structure

```
SafeVaultApp/
├── Helpers/
│   └── ValidationHelpers.cs      # Input validation and XSS protection
├── Services/
│   └── AuthenticationService.cs  # Secure authentication with parameterized queries
├── Tests/
│   └── SecurityTests.cs          # Comprehensive security testing suite
├── Database/
│   └── SafeVaultSchema.sql       # Secure database schema with audit logging
├── Program.cs                    # Main application demonstrating all features
├── SafeVaultApp.csproj          # Project configuration
└── README.md                    # This file
```

## 🚀 Getting Started

### Prerequisites
- .NET 6.0 or later
- SQL Server or SQL Server Express
- Visual Studio Code or Visual Studio

### Installation

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd SafeVaultApp
   ```

2. **Restore dependencies**
   ```bash
   dotnet restore
   ```

3. **Set up the database**
   - Create a SQL Server database named `SafeVaultDB`
   - Run the `Database/SafeVaultSchema.sql` script to create tables and procedures
   - Update the connection string in `Program.cs` to match your SQL Server instance

4. **Build the project**
   ```bash
   dotnet build
   ```

5. **Run the application**
   ```bash
   dotnet run
   ```

## 🧪 Security Testing

The application includes a comprehensive security testing suite that validates:

- **Input validation** against various attack vectors
- **XSS protection** with multiple payload types
- **Password validation** with strength requirements
- **Email validation** with proper format checking
- **Input sanitization** effectiveness

Run the tests by executing the application - the security tests run automatically on startup.

## 🔍 Key Security Implementations

### Input Validation (ValidationHelpers.cs)
```csharp
public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
{
    if (string.IsNullOrEmpty(input))
        return false;

    var validCharacters = allowedSpecialCharacters.ToHashSet();
    return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
}
```

### XSS Protection
```csharp
public static bool IsValidXSSInput(string input)
{
    if (string.IsNullOrEmpty(input))
        return true;

    string lowerInput = input.ToLower();
    if (lowerInput.Contains("<script") || lowerInput.Contains("<iframe"))
        return false;

    // Additional dangerous pattern checks...
    return true;
}
```

### Secure Login with Parameterized Queries
```csharp
public bool LoginUser(string username, string password)
{
    // Input validation first
    if (!ValidationHelpers.IsValidInput(username) || 
        !ValidationHelpers.IsValidInput(password, allowedSpecialCharacters))
        return false;

    // Parameterized query prevents SQL injection
    string query = "SELECT PasswordHash, Salt FROM Users WHERE Username = @Username AND IsActive = 1";
    using (var command = new SqlCommand(query, connection))
    {
        command.Parameters.AddWithValue("@Username", username);
        // ... secure password verification
    }
}
```

## 📋 OWASP Top 10 Compliance

This application addresses the following OWASP Top 10 vulnerabilities:

1. **A03:2021 – Injection**: Prevented through input validation and parameterized queries
2. **A07:2021 – Cross-Site Scripting (XSS)**: Blocked through input validation and sanitization
3. **A02:2021 – Cryptographic Failures**: Addressed with proper password hashing (PBKDF2)
4. **A07:2021 – Identification and Authentication Failures**: Mitigated with account lockout and secure sessions
5. **A09:2021 – Security Logging**: Implemented through comprehensive audit logging

## 🛡️ Security Best Practices Implemented

### Code Level
- ✅ Input validation on all user inputs
- ✅ Parameterized queries for all database operations
- ✅ Secure password hashing with salt
- ✅ XSS protection and input sanitization
- ✅ Comprehensive error handling without information disclosure
- ✅ Modular code structure with clear separation of concerns

### Database Level
- ✅ Stored procedures for data access
- ✅ Audit logging for security events
- ✅ Account lockout mechanisms
- ✅ Minimal database permissions
- ✅ Secure schema design

### Application Level
- ✅ Comprehensive security testing
- ✅ Clear documentation and comments
- ✅ OWASP guideline compliance
- ✅ Proper exception handling

## 🔧 Configuration

### Connection String Security
In production environments:
- Store connection strings in secure configuration (Azure Key Vault, appsettings.json with user secrets)
- Use managed identities or service principals for database authentication
- Enable connection encryption (TLS/SSL)

### Environment Variables
Consider using environment variables for sensitive configuration:
```bash
export SAFEVAULT_CONNECTION_STRING="Server=...;Database=SafeVaultDB;..."
export SAFEVAULT_ENCRYPTION_KEY="your-encryption-key-here"
```

## 📊 Testing Results

The application automatically runs security tests on startup. Expected results:

- **Input Validation Tests**: All malicious inputs should be rejected
- **XSS Protection Tests**: All XSS payloads should be blocked
- **Password Validation Tests**: Weak passwords should be rejected
- **Email Validation Tests**: Invalid email formats should be rejected
- **Sanitization Tests**: Dangerous content should be cleaned

## 🤝 Contributing

1. Follow secure coding practices
2. Add tests for new security features
3. Update documentation for any security changes
4. Run the full security test suite before submitting changes

## 📚 Further Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

## ⚠️ Security Notice

This application is designed for educational purposes and demonstration of secure coding principles. For production use:

- Implement additional security layers (WAF, rate limiting, etc.)
- Regular security audits and penetration testing
- Keep dependencies updated
- Implement proper monitoring and alerting
- Follow your organization's security policies

## 📄 License

This project is provided for educational purposes. Please ensure compliance with your organization's security policies and applicable laws when implementing similar solutions.
