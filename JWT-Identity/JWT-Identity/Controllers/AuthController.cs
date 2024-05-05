using JWT_Identity.Models;
using JWT_Identity.Services;
using JWT_Project.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthServices _authServices;
        public AuthController(IAuthServices authServices)
        {
            _authServices = authServices;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            AuthModel authModel =  await _authServices.Register(model);
            if (!authModel.IsAuthenticated)
                return BadRequest(authModel.Message);

            SetTokenInCookies(authModel.RefreshToken,authModel.RefreshTokenExpiration);
            return Ok(authModel);
        }

        [HttpPost("AddRole")]
        public async Task<IActionResult> AddRole([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            string addRoleToUser =  await _authServices.AddRoleAsync(model);
            if (!string.IsNullOrEmpty(addRoleToUser))
                return BadRequest(addRoleToUser);
            return Ok(model);
        }

        [HttpPost("GetToken")]
        public async Task<IActionResult> GetToken([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            AuthModel authModel = await _authServices.GetTokenAsync(model);
            if (!authModel.IsAuthenticated)
                return BadRequest(authModel.Message);
            if (authModel.RefreshToken != null)
                SetTokenInCookies(authModel.RefreshToken,authModel.RefreshTokenExpiration);
            return Ok(authModel);
        }

        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            string refreshToken = Request.Cookies["refreshToken"];
            AuthModel authModel = await _authServices.RefreshTokenAsync(refreshToken);
            if (!authModel.IsAuthenticated)
                return BadRequest(authModel);
            if (authModel != null)
                SetTokenInCookies(authModel.RefreshToken,authModel.RefreshTokenExpiration);
            return Ok(authModel);
        }
        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeModel revoke)
        {
            string token = !string.IsNullOrEmpty(revoke.Token)? revoke.Token: Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(token))
                return BadRequest("Token Is Required!");
            bool revokeToken = await _authServices.RevokeTokenAsync(token);
            if (!revokeToken)
                return BadRequest("Token Invalid");
            return Ok();
        }
        private void SetTokenInCookies(string token,DateTime expire)
        {
            CookieOptions cookieOptions = new CookieOptions()
            {
                HttpOnly = true,
                Expires = expire
            };
            Response.Cookies.Append("refreshToken",token, cookieOptions);
        }
    }
}
