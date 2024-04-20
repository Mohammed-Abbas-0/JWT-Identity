using JWT_Identity.Data;
using JWT_Identity.Models;
using JWT_Project.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWT_Identity.Services
{
    public class AuthServices : IAuthServices
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly JWT _jwt;
        public AuthServices(UserManager<AppUser> userManager,  IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
        }


        public async Task<AuthModel> Register(RegisterModel register)
        {
            if(await _userManager.FindByEmailAsync(register.Email) is not null)
                return new AuthModel { Message = "Email is already registered!" };

            if (await _userManager.FindByNameAsync(register.Username) is not null)
                return new AuthModel { Message = "Username is already registered!" };
            AppUser user = new()
            {
                UserName = register.Username,
                Email = register.Email,
                FirstName = register.FirstName,
                LastName = register.LastName
            };
            IdentityResult result = await _userManager.CreateAsync(user, register.Password);
            #region ERRORS
            if (!result.Succeeded)
            {
                StringBuilder errors = new();

                foreach (var error in result.Errors)
                    errors.Append($"{error.Description},");

                return new AuthModel { Message = errors.ToString() };
            }
            #endregion

            await _userManager.AddToRoleAsync(user, "User");

            JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);

            return new AuthModel
            {
                Email = user.Email,
                //ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName
            };
        }
        private async Task<JwtSecurityToken> CreateJwtToken(AppUser user)
        {
            // الحصول على المطالبات المرتبطة بالمستخدم
            var userClaims = await _userManager.GetClaimsAsync(user);

            // الحصول على الأدوار (الرولز) المرتبطة بالمستخدم
            var roles = await _userManager.GetRolesAsync(user);

            // إنشاء قائمة لتخزين المطالبات المرتبطة بالأدوار
            var roleClaims = new List<Claim>();

            // إضافة مطالبات الأدوار إلى القائمة
            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            // إنشاء مجموعة من المطالبات للتوكن JWT
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName), // Sub: اسم المستخدم
                //"jti" هو رقم العنصر
                //(JWT ID) ويُستخدم لتمييز الرموز
                //JWT المختلفة،
                //ويُمكن استخدامه لتجنب تكرار
                //استخدام الرموز.
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Jti: مُعرف فريد للتوكن
                new Claim(JwtRegisteredClaimNames.Email, user.Email), // البريد الإلكتروني
                new Claim("uid", user.Id) // مُعرف المستخدم
            }
            .Union(userClaims) // دمج المطالبات المستخدمة مع المطالبات الأصلية
            .Union(roleClaims); // دمج مطالبات الأدوار

            // إنشاء مفتاح أمان متماثل لتوقيع التوكن
            SymmetricSecurityKey symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));

            // إنشاء بيانات اعتماد لتوقيع التوكن
            SigningCredentials signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            // إنشاء توكن JWT
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.ValidIssuer, // المُصدر الصالح للتوكن
                audience: _jwt.ValidAudience, // المستقبل الصالح للتوكن
                claims: claims, // المطالبات المضمنة في التوكن
                                // expires: DateTime.Now.AddDays(_jwt.DurationInMinutes), // تاريخ انتهاء الصلاحية للتوكن
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials); // بيانات الاعتماد للتوقيع

            // إرجاع التوكن JWT
            return jwtSecurityToken;
        }

    }
}
