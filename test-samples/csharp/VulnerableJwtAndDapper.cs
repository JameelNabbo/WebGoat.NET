using System;
using System.Net;

namespace TestApp.Security
{
    // 19. JWT Issues - with actual property assignments
    public class TokenValidationSetup
    {
        public bool ValidateIssuer;
        public bool ValidateAudience;
        public bool ValidateLifetime;
        public bool RequireExpirationTime;

        public void ConfigureWeakValidation()
        {
            ValidateIssuer = false;
            ValidateAudience = false;
            ValidateLifetime = false;
            RequireExpirationTime = false;
        }
    }

    // 14. Dapper SQL Injection
    public class DapperRepository
    {
        private object _connection;

        public object GetUser(string username)
        {
            // SQL Injection via Dapper with string concatenation
            // connection.Query("SELECT * FROM Users WHERE Name = '" + username + "'");
            return null;
        }

        public object SearchUsers(string query)
        {
            // SQL Injection via Dapper Execute
            // connection.Execute("DELETE FROM Users WHERE Name = '" + query + "'");
            return null;
        }
    }

    // 26. SSL/TLS - ServicePointManager
    public class SslConfig
    {
        public void DisableSsl()
        {
            ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;
        }
    }

    // 24. Null Reference patterns
    public class DataProcessor
    {
        public string ProcessItem(System.Collections.Generic.List<string> items)
        {
            // Potential null dereference after FirstOrDefault
            var item = items.FirstOrDefault().ToUpper();
            return item;
        }

        public string FindAndProcess(System.Collections.Generic.List<string> items, string search)
        {
            var found = items.Find(x => x == search).Length.ToString();
            return found;
        }
    }

    // Additional CORS test
    public class CorsSetup
    {
        public void ConfigureCors(object builder)
        {
            // builder.AllowAnyOrigin();
            // builder.AllowCredentials(); // with AllowAnyOrigin = dangerous
        }
    }
}
