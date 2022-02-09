using app1.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace app1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApiSecurityController : ControllerBase
    {
        private readonly IConfiguration configuration;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;

        public ApiSecurityController(
            IConfiguration configuration, 
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager
            ) {
            this.configuration = configuration;
            this.signInManager = signInManager;
            this.userManager = userManager;
        }


        [AllowAnonymous]
        [Route("login")]
         public async Task<IActionResult> TokenAuth(SigninViewModel model)
        {
            var issuer = configuration["Tokens:Issuer"];
            var audience = configuration["Tokens:Audience"];
            var key = configuration["Tokens:Key"];
            if (ModelState.IsValid)
            {
                var signInResult = await signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);
                if (signInResult.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(model.Username);
                    if (user != null)
                    {
                        var claims = new[]
                        {
                            new Claim(JwtRegisteredClaimNames.Email, user.Email),
                            new Claim(JwtRegisteredClaimNames.Jti, user.Id)
                        };

                        var keyBytes = Encoding.UTF8.GetBytes(key);
                        var jwtKey = new SymmetricSecurityKey(keyBytes);
                        var credentials = new SigningCredentials(jwtKey, SecurityAlgorithms.HmacSha256);
                        var token = new JwtSecurityToken(issuer, audience, claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: credentials);
                        return Ok(new { token= new JwtSecurityTokenHandler().WriteToken(token) });
                    }
                }
            }
            return BadRequest();
        }
    }
}
