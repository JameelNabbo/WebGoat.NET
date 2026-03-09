using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;

namespace TestApp.AspNet
{
    // 13. ASP.NET Core CORS - configured in Startup
    public class Startup
    {
        public void ConfigureServices(object services)
        {
            // Dangerous CORS configuration would be:
            // services.AddCors(o => o.AddDefaultPolicy(b => b.AllowAnyOrigin().AllowCredentials()));
        }

        public void Configure(object app)
        {
            // 20. Information Disclosure - dev exception page unconditionally
            // app.UseDeveloperExceptionPage();
        }
    }

    // 13. Controller without Authorize - Missing Authorization
    public class PublicApiController : ControllerBase
    {
        // 21. Open Redirect
        [HttpGet]
        public IActionResult Login([FromQuery] string returnUrl)
        {
            // Authenticate user...
            return Redirect(returnUrl);
        }

        // 28. AllowAnonymous on sensitive endpoint
        [AllowAnonymous]
        [HttpPost]
        public IActionResult DeleteUser([FromBody] string userId)
        {
            // Deleting user without authentication
            return Ok("deleted");
        }

        // 28. AllowAnonymous on admin settings
        [AllowAnonymous]
        [HttpPost]
        public IActionResult UpdateSettings([FromBody] object settings)
        {
            return Ok();
        }

        // 29. CSRF - IgnoreAntiforgeryToken on POST
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public IActionResult TransferMoney([FromBody] object transfer)
        {
            return Ok("transferred");
        }

        // 17. Mass Assignment - Model binding without Bind attribute
        [HttpPost]
        public IActionResult CreateUser(UserModel model)
        {
            // model may include IsAdmin, Role, etc. that should not be user-settable
            return Ok(model);
        }

        // 17. Another mass assignment
        [HttpPut]
        public IActionResult UpdateProfile(UserProfileDto profile)
        {
            return Ok(profile);
        }
    }

    // 15. SignalR Hub without authentication
    public class ChatHub : Hub
    {
        public async Task SendMessage(string user, string message)
        {
            await Clients.All.SendAsync("ReceiveMessage", user, message);
        }

        public async Task BroadcastData(string data)
        {
            await Clients.All.SendAsync("DataReceived", data);
        }
    }

    // 15. Another Hub without auth
    public class NotificationHub : Hub
    {
        public async Task Subscribe(string channel)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, channel);
        }
    }

    // 18. Cookie Issues
    public class CookieController : Controller
    {
        [HttpPost]
        public IActionResult SetAuthCookie()
        {
            var options = new CookieOptions();
            options.HttpOnly = false;
            options.Secure = false;
            options.SameSite = SameSiteMode.None;
            Response.Cookies.Append("auth_token", "secret_value", options);
            return Ok();
        }
    }

    // 19. JWT Issues
    public class JwtConfig
    {
        public void ConfigureJwt()
        {
            var tokenParams = new object(); // TokenValidationParameters
            // These would be real assignments:
            // tokenParams.ValidateIssuer = false;
            // tokenParams.ValidateAudience = false;
            // tokenParams.ValidateLifetime = false;
            // tokenParams.RequireExpirationTime = false;
        }
    }

    // 16. Blazor MarkupString
    public class BlazorComponent
    {
        public object RenderUserContent(string userInput)
        {
            // XSS via MarkupString
            return new MarkupString("<div>" + userInput + "</div>");
        }
    }

    // Dummy types for compilation
    public class MarkupString
    {
        public MarkupString(string value) { }
    }

    public class UserModel
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public bool IsAdmin { get; set; }
        public string Role { get; set; }
    }

    public class UserProfileDto
    {
        public string Name { get; set; }
        public string Bio { get; set; }
    }
}
