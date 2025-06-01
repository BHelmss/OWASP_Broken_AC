# OWASP_Broken_Access_Control

## What is Access Control?

- Access Control is a security mechanism used to control which users or systems are allowed to access a particular resource or system.

## 4 Main Types

1. Mandatory Access Control (MAC): Access to a resource is determined by a central authority and not the owner. Typical access control structure used in clearance environments.
2. Discretionary Access Control (DAC): The owner controls access to the resource. Commonly used in file systems.
3. Attribute-Based Access Control(ABAC): Access is granted based on an attribute or series of attributes such as time of day, location, role, etc.
4. Role-Based Access Control(RBAC): A user is given a role and access to resources are granted to the role and not the user directly. Commonly used in enterprise systems. 

## What is Broken Access Control?

- Broken access control refers to access control systems breaking and failing to appropriately restrict access to resources.
  
1. Horizontal privelege escalation: occurs when an attacker can access resources or data belonging to other users with the same level of access.
2. Vertical privilege escalation: occurs when an attacker can access resources or data belonging to users with higher access levels. 
3. Insufficient access control checks:  occur when access control checks are not performed correctly or consistently, allowing an attacker to bypass them.
4. Insecure Direct Object Reference(IDOR): occur when an attacker can access a resource or data by exploiting a weakness in the application’s access control mechanisms. For example, an application might use predictable or easily guessable identifiers for sensitive data, making it easier for an attacker to access.

## The web app for this lab:

- When you browse a web application as a penetration tester, imagine what the underlying code looks like and what vulnerabilities come to mind for each functionality, request, and response.
- The web application for this room features a Dashboard, Login, and Registration form that enables users to access the dashboard of the website. From a web app pentester standpoint, the pentester will usually register an account. After the registration, the pentester will then try to check the login function for any access control vulnerabilities.

![image](https://github.com/user-attachments/assets/b35e1354-4c1d-4a86-b385-264bfb330772)

## Capturing http requests on the vulnerable app with Burp

- The captured Post function when attempting to login with the credentials root@gmail.com:root

![image](https://github.com/user-attachments/assets/eab991dc-f54a-4ef8-a772-cfa9d97df8f2)

- Based on the screenshot displayed above, we can observe that upon
completing the login process, the web application will give us a JSON
response that contains the status, message, first_name, last_name,
is_admin, and redirect_link which the server uses to redirect the user
to the `dashboard.php` with the parameter “isadmin” in the
URL.
- The target web application does not have any implemented security
headers, which indicates that there are no preventative measures (like a
first line of defense) in place to protect the web application against
certain types of attacks.
- The target web application is running on a Linux operating system
(`Debian`) and is using Apache web server
(`Apache/2.4.38`). This information can be useful in
identifying potential security vulnerabilities that may exist in the
target web application.
- The target web application utilizes `PHP/8.0.19` as its
backend programming language. This information is important for
understanding the technology stack of the application and identifying
potential security vulnerabilities or compatibility issues that may
arise with other software components.
- The target web application redirects the user to the dashboard with
a parameter that we can possibly test for privilege escalation
vulnerabilities.

## Exploiting Web App

- We can copy the redirect link to the url bar and modifying the value from false to true.

![image](https://github.com/user-attachments/assets/5fcf68f1-9997-43a2-a29d-54aaeddd213f)

![image](https://github.com/user-attachments/assets/7ee35933-0338-43af-b0ae-c4fa4a71ef67)

![image](https://github.com/user-attachments/assets/ef88e99c-666f-4c6b-9e8f-6c5b7fca983f)

- This then redirects me to the admin.php page.
- If i go back and create an account with non admin privs. I can go to this admin.php and give the account admin privileges.

![image](https://github.com/user-attachments/assets/3b440611-b449-4ce1-9da0-0d1c6bb0595c)

## Mitigation

There are several steps that can be taken to mitigate the risk of
broken access control vulnerabilities in PHP applications:

1. **Implement Role-Based Access Control (RBAC)**:
Role-based access control (RBAC) is a method of regulating access to
computer or network resources based on the roles of individual users
within an enterprise. By defining roles in an organization and assigning
access rights to these roles, you can control what actions a user can
perform on a system. The provided code snippet illustrates how you can
define roles (such as ‘admin’, ‘editor’, or ‘user’) and the permissions
associated with them. The `hasPermission` function checks if
a user of a certain role has a specified permission.
    
    ```bash
    / Define roles and permissions
     $roles = [
         'admin' => ['create', 'read', 'update', 'delete'],
         'editor' => ['create', 'read', 'update'],
         'user' => ['read'],
     ];
    
     // Check user permissions
     function hasPermission($userRole, $requiredPermission) {
         global $roles;
         return in_array($requiredPermission, $roles[$userRole]);
     }
    
     // Example usage
     if (hasPermission('admin', 'delete')) {
         // Allow delete operation
     } else {
         // Deny delete operation
     }
    ```
    
2. **Use Parameterized Queries**: Parameterized queries
are a way to protect PHP applications from SQL Injection attacks, where
malicious users could potentially gain unauthorized access to your
database. By using placeholders instead of directly including user input
into the SQL query, you can significantly reduce the risk of SQL
Injection attacks. The provided example demonstrates how a query can be
made secure using prepared statements, which separates SQL syntax from
data and handles user input safely.
    
    ```bash
    // Example of vulnerable query
     $username = $_POST['username'];
     $password = $_POST['password'];
     $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    
     // Example of secure query using prepared statements
     $username = $_POST['username'];
     $password = $_POST['password'];
     $stmt = $pdo->prepare("SELECT * FROM users WHERE username=? AND password=?");
     $stmt->execute([$username, $password]);
     $user = $stmt->fetch();
    ```
    
3. **Proper Session Management**: Proper session
management ensures that authenticated users have timely and appropriate
access to resources, thereby reducing the risk of unauthorized access to
sensitive information. Session management includes using secure cookies,
setting session timeouts, and limiting the number of active sessions a
user can have. The code snippet shows how to initialize a session, set
session variables and check for session validity by looking at the last
activity time.
    
    ```bash
    // Start session
     session_start();
    
     // Set session variables
     $_SESSION['user_id'] = $user_id;
     $_SESSION['last_activity'] = time();
    
     // Check if session is still valid
     if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
         // Session has expired
         session_unset();
         session_destroy();
     }
     
    ```
    
4. **Use Secure Coding Practices**: Secure coding
practices involve methods to prevent the introduction of security
vulnerabilities. Developers should sanitize and validate user input to
prevent malicious data from causing harm and avoid using insecure
functions or libraries. The given example shows how to sanitize user
input using PHP’s `filter_input` function and demonstrates
how to securely hash a password using `password_hash` instead
of an insecure function like `md5`.
    
    ```bash
     // Validate user input
     $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
     $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
    
     // Avoid insecure functions
     // Example of vulnerable code using md5
     $password = md5($password);
     // Example of secure code using password_hash
     $password = password_hash($password, PASSWORD_DEFAULT);
      
    ```
