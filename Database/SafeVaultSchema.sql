-- SafeVault Database Schema
-- Demonstrates secure database design principles
-- Following OWASP guidelines for secure data storage

-- Create the SafeVault database
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'SafeVaultDB')
BEGIN
    CREATE DATABASE SafeVaultDB;
END
GO

USE SafeVaultDB;
GO

-- Create Users table with secure design
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Users')
BEGIN
    CREATE TABLE Users (
        UserId INT IDENTITY(1,1) PRIMARY KEY,
        Username NVARCHAR(50) NOT NULL UNIQUE,
        PasswordHash NVARCHAR(255) NOT NULL, -- Store hashed passwords only
        Salt NVARCHAR(255) NOT NULL, -- Salt for password hashing
        Email NVARCHAR(255) NOT NULL UNIQUE,
        FirstName NVARCHAR(100),
        LastName NVARCHAR(100),
        CreatedDate DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
        LastLoginDate DATETIME2 NULL,
        IsActive BIT NOT NULL DEFAULT 1,
        FailedLoginAttempts INT NOT NULL DEFAULT 0,
        LockedUntil DATETIME2 NULL,
        UserRole NVARCHAR(20) NOT NULL DEFAULT 'user', -- Role-based authorization
        
        -- Constraints for security
        CONSTRAINT CK_Users_Username_Length CHECK (LEN(Username) >= 3),
        CONSTRAINT CK_Users_Email_Format CHECK (Email LIKE '%@%.%'),
        CONSTRAINT CK_Users_Role CHECK (UserRole IN ('user', 'admin', 'moderator'))
    );
    
    -- Create indexes for performance
    CREATE INDEX IX_Users_Username ON Users(Username);
    CREATE INDEX IX_Users_Email ON Users(Email);
    CREATE INDEX IX_Users_IsActive ON Users(IsActive);
END
GO

-- Create UserSessions table for secure session management
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'UserSessions')
BEGIN
    CREATE TABLE UserSessions (
        SessionId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        UserId INT NOT NULL,
        SessionToken NVARCHAR(255) NOT NULL UNIQUE,
        CreatedDate DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
        ExpiryDate DATETIME2 NOT NULL,
        IsActive BIT NOT NULL DEFAULT 1,
        IPAddress NVARCHAR(45), -- Support IPv6
        UserAgent NVARCHAR(500),
        
        CONSTRAINT FK_UserSessions_Users FOREIGN KEY (UserId) REFERENCES Users(UserId)
    );
    
    -- Create indexes
    CREATE INDEX IX_UserSessions_UserId ON UserSessions(UserId);
    CREATE INDEX IX_UserSessions_Token ON UserSessions(SessionToken);
    CREATE INDEX IX_UserSessions_Expiry ON UserSessions(ExpiryDate);
END
GO

-- Create AuditLog table for security monitoring
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AuditLog')
BEGIN
    CREATE TABLE AuditLog (
        LogId BIGINT IDENTITY(1,1) PRIMARY KEY,
        UserId INT NULL,
        Action NVARCHAR(100) NOT NULL,
        EntityType NVARCHAR(50),
        EntityId NVARCHAR(50),
        OldValues NVARCHAR(MAX),
        NewValues NVARCHAR(MAX),
        IPAddress NVARCHAR(45),
        UserAgent NVARCHAR(500),
        Timestamp DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
        
        CONSTRAINT FK_AuditLog_Users FOREIGN KEY (UserId) REFERENCES Users(UserId)
    );
    
    -- Create indexes for performance
    CREATE INDEX IX_AuditLog_UserId ON AuditLog(UserId);
    CREATE INDEX IX_AuditLog_Action ON AuditLog(Action);
    CREATE INDEX IX_AuditLog_Timestamp ON AuditLog(Timestamp);
END
GO

-- Create stored procedures for secure data access
-- Procedure for user authentication (demonstrates parameterized queries)
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_AuthenticateUser')
    DROP PROCEDURE sp_AuthenticateUser;
GO

CREATE PROCEDURE sp_AuthenticateUser
    @Username NVARCHAR(50),
    @IPAddress NVARCHAR(45) = NULL,
    @UserAgent NVARCHAR(500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Check for account lockout
    DECLARE @IsLocked BIT = 0;
    DECLARE @UserId INT;
    
    SELECT @UserId = UserId, @IsLocked = CASE 
        WHEN LockedUntil IS NOT NULL AND LockedUntil > GETUTCDATE() THEN 1 
        ELSE 0 
    END
    FROM Users 
    WHERE Username = @Username AND IsActive = 1;
    
    IF @IsLocked = 1
    BEGIN
        -- Log failed attempt due to lockout
        INSERT INTO AuditLog (UserId, Action, IPAddress, UserAgent)
        VALUES (@UserId, 'LOGIN_ATTEMPT_LOCKED', @IPAddress, @UserAgent);
        
        SELECT 'LOCKED' AS Status, NULL AS PasswordHash, NULL AS Salt;
        RETURN;
    END
    
    -- Return user data for password verification
    SELECT 
        CASE WHEN u.UserId IS NOT NULL THEN 'FOUND' ELSE 'NOT_FOUND' END AS Status,
        u.PasswordHash,
        u.Salt,
        u.UserId
    FROM Users u
    WHERE u.Username = @Username AND u.IsActive = 1;
    
    -- Log authentication attempt
    INSERT INTO AuditLog (UserId, Action, IPAddress, UserAgent)
    VALUES (@UserId, 'LOGIN_ATTEMPT', @IPAddress, @UserAgent);
END
GO

-- Procedure for updating login attempts and lockout
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_UpdateLoginAttempt')
    DROP PROCEDURE sp_UpdateLoginAttempt;
GO

CREATE PROCEDURE sp_UpdateLoginAttempt
    @Username NVARCHAR(50),
    @Success BIT,
    @IPAddress NVARCHAR(45) = NULL,
    @UserAgent NVARCHAR(500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @UserId INT;
    SELECT @UserId = UserId FROM Users WHERE Username = @Username;
    
    IF @Success = 1
    BEGIN
        -- Successful login - reset failed attempts and update last login
        UPDATE Users 
        SET FailedLoginAttempts = 0, 
            LockedUntil = NULL,
            LastLoginDate = GETUTCDATE()
        WHERE Username = @Username;
        
        INSERT INTO AuditLog (UserId, Action, IPAddress, UserAgent)
        VALUES (@UserId, 'LOGIN_SUCCESS', @IPAddress, @UserAgent);
    END
    ELSE
    BEGIN
        -- Failed login - increment attempts and check for lockout
        DECLARE @FailedAttempts INT;
        
        UPDATE Users 
        SET FailedLoginAttempts = FailedLoginAttempts + 1
        WHERE Username = @Username;
        
        SELECT @FailedAttempts = FailedLoginAttempts 
        FROM Users 
        WHERE Username = @Username;
        
        -- Lock account after 5 failed attempts for 30 minutes
        IF @FailedAttempts >= 5
        BEGIN
            UPDATE Users 
            SET LockedUntil = DATEADD(MINUTE, 30, GETUTCDATE())
            WHERE Username = @Username;
            
            INSERT INTO AuditLog (UserId, Action, IPAddress, UserAgent)
            VALUES (@UserId, 'ACCOUNT_LOCKED', @IPAddress, @UserAgent);
        END
        ELSE
        BEGIN
            INSERT INTO AuditLog (UserId, Action, IPAddress, UserAgent)
            VALUES (@UserId, 'LOGIN_FAILED', @IPAddress, @UserAgent);
        END
    END
END
GO

-- Create a view for safe user data access (excludes sensitive information)
IF EXISTS (SELECT * FROM sys.views WHERE name = 'vw_SafeUserData')
    DROP VIEW vw_SafeUserData;
GO

CREATE VIEW vw_SafeUserData
AS
SELECT 
    UserId,
    Username,
    Email,
    FirstName,
    LastName,
    CreatedDate,
    LastLoginDate,
    IsActive,
    UserRole
FROM Users
WHERE IsActive = 1;
GO

-- Create stored procedure for role-based authorization
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_CheckUserRole')
    DROP PROCEDURE sp_CheckUserRole;
GO

CREATE PROCEDURE sp_CheckUserRole
    @Username NVARCHAR(50),
    @RequiredRole NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @UserRole NVARCHAR(20);
    DECLARE @IsActive BIT;
    
    SELECT @UserRole = UserRole, @IsActive = IsActive
    FROM Users
    WHERE Username = @Username;
    
    -- Check if user exists and is active
    IF @IsActive IS NULL OR @IsActive = 0
    BEGIN
        SELECT 'INACTIVE' AS Status, NULL AS UserRole;
        RETURN;
    END
    
    -- Check role authorization
    IF @UserRole = 'admin' OR @UserRole = @RequiredRole
    BEGIN
        SELECT 'AUTHORIZED' AS Status, @UserRole AS UserRole;
    END
    ELSE
    BEGIN
        SELECT 'UNAUTHORIZED' AS Status, @UserRole AS UserRole;
    END
END
GO

-- Create stored procedure for updating user roles (admin only)
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_UpdateUserRole')
    DROP PROCEDURE sp_UpdateUserRole;
GO

CREATE PROCEDURE sp_UpdateUserRole
    @AdminUsername NVARCHAR(50),
    @TargetUsername NVARCHAR(50),
    @NewRole NVARCHAR(20),
    @IPAddress NVARCHAR(45) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @AdminRole NVARCHAR(20);
    DECLARE @AdminUserId INT;
    DECLARE @TargetUserId INT;
    DECLARE @OldRole NVARCHAR(20);
    
    -- Verify admin privileges
    SELECT @AdminRole = UserRole, @AdminUserId = UserId
    FROM Users
    WHERE Username = @AdminUsername AND IsActive = 1;
    
    IF @AdminRole != 'admin'
    BEGIN
        -- Log unauthorized role change attempt
        INSERT INTO AuditLog (UserId, Action, IPAddress)
        VALUES (@AdminUserId, 'UNAUTHORIZED_ROLE_CHANGE_ATTEMPT', @IPAddress);
        
        SELECT 'UNAUTHORIZED' AS Status;
        RETURN;
    END
    
    -- Get target user info
    SELECT @TargetUserId = UserId, @OldRole = UserRole
    FROM Users
    WHERE Username = @TargetUsername AND IsActive = 1;
    
    IF @TargetUserId IS NULL
    BEGIN
        SELECT 'USER_NOT_FOUND' AS Status;
        RETURN;
    END
    
    -- Update role
    UPDATE Users
    SET UserRole = @NewRole
    WHERE UserId = @TargetUserId;
    
    -- Log role change
    INSERT INTO AuditLog (UserId, Action, OldValues, NewValues, IPAddress)
    VALUES (@AdminUserId, 'ROLE_CHANGED', 
            CONCAT('Target: ', @TargetUsername, ', OldRole: ', @OldRole),
            CONCAT('Target: ', @TargetUsername, ', NewRole: ', @NewRole),
            @IPAddress);
    
    SELECT 'SUCCESS' AS Status;
END
GO

-- Grant appropriate permissions (example - adjust based on your security model)
-- In production, create specific database users with minimal required permissions

-- Sample data for testing (DO NOT use in production)
-- This demonstrates secure password storage with salt and hash
IF NOT EXISTS (SELECT * FROM Users WHERE Username = 'testuser')
BEGIN
    INSERT INTO Users (Username, PasswordHash, Salt, Email, FirstName, LastName, UserRole)
    VALUES (
        'testuser',
        'hashed_password_here', -- In real implementation, this would be a proper PBKDF2 hash
        'random_salt_here',     -- In real implementation, this would be a cryptographically secure salt
        'test@example.com',
        'Test',
        'User',
        'user'
    );
END
GO

-- Create admin user for testing
IF NOT EXISTS (SELECT * FROM Users WHERE Username = 'admin')
BEGIN
    INSERT INTO Users (Username, PasswordHash, Salt, Email, FirstName, LastName, UserRole)
    VALUES (
        'admin',
        'admin_hashed_password_here', -- In real implementation, this would be a proper PBKDF2 hash
        'admin_random_salt_here',     -- In real implementation, this would be a cryptographically secure salt
        'admin@safevault.com',
        'System',
        'Administrator',
        'admin'
    );
END
GO

PRINT 'SafeVault database schema created successfully!';
PRINT 'Remember to:';
PRINT '1. Use proper connection string encryption in production';
PRINT '2. Implement proper database user permissions';
PRINT '3. Enable database auditing and monitoring';
PRINT '4. Regular security updates and patches';
PRINT '5. Backup and disaster recovery procedures';
