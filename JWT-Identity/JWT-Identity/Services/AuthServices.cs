using JWT_Identity.Data;
using JWT_Identity.Models;
using JWT_Project.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JWT_Identity.Services
{
    public class AuthServices : IAuthServices
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _identityRole;
        private readonly JWT _jwt;
        public AuthServices(UserManager<AppUser> userManager, RoleManager<IdentityRole> identityRole,  IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _identityRole = identityRole;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            AppUser user = await _userManager.FindByIdAsync(model.UserId);

            if (await _identityRole.RoleExistsAsync(model.Role) || user is null)
                return "Invalid user ID or Role";

            if (await _userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";
            var result = await _userManager.AddToRoleAsync(user,model.Role);

            return result.Succeeded ? string.Empty : "Sonething went wrong";

        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            AuthModel authModel = new();
            AppUser user = await _userManager.FindByEmailAsync(model.Email);

            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return new AuthModel() { Message = "Email Or Password is incorrect." };

            JwtSecurityToken jwtToken = await CreateJwtToken(user);
            IList<string> Roles = await _userManager.GetRolesAsync(user);

            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.IsAuthenticated = true;

            authModel.Roles = Roles.ToList();

            if (user.RefreshTokens.Any(idx=>idx.IsActive))
            {
                RefreshToken activeToken =  user.RefreshTokens.FirstOrDefault(idx=>idx.IsActive);
                authModel.RefreshToken = activeToken.Token;
                authModel.RefreshTokenExpiration = activeToken.ExpiresOn;
            }
            else
            {
                RefreshToken refreshToken = GenerateRefreshToken();
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExpiration = refreshToken.ExpiresOn;
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);
            
            }

            return authModel;
        }
        private RefreshToken GenerateRefreshToken()
        {
            byte[] randomNumber = new byte[32];

            using var generator = new RNGCryptoServiceProvider();

            generator.GetBytes(randomNumber);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddMinutes(50),
                CreatedOn = DateTime.UtcNow
            };
        }

        public async Task<AuthModel> RefreshTokenAsync(string token)
        {
            AuthModel authModel = new();
            AppUser user = await _userManager.Users.FirstOrDefaultAsync(idx => idx.RefreshTokens.Any(col => col.Token == token));
            if (user is null)
            {
                authModel.Message = "Invalid Token";
                return authModel;
            }

            RefreshToken refreshToken = user.RefreshTokens.Single(idx => idx.Token == token);
            if (!refreshToken.IsActive)
            {
                authModel.Message = "Inactive Token";
                return authModel;
            }

            refreshToken.RevokedOn = DateTime.UtcNow;

            var newRefreshToken = GenerateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            await _userManager.UpdateAsync(user);

            var jwtToken = await CreateJwtToken(user);
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            var roles = await _userManager.GetRolesAsync(user);
            authModel.Roles = roles.ToList();
            authModel.RefreshToken = newRefreshToken.Token;
            authModel.RefreshTokenExpiration = newRefreshToken.ExpiresOn;

            return authModel;
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
            await _userManager.AddToRoleAsync(user, "Admin");

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
        public async Task<bool> RevokeTokenAsync(string token)
        {
            AppUser user = await _userManager.Users.FirstOrDefaultAsync(idx => idx.RefreshTokens.Any(col => col.Token == token));
            if (user is null)
                return false;

            RefreshToken refreshToken = user.RefreshTokens.Single(idx => idx.Token == token);
            if (!refreshToken.IsActive)
                return false;

            refreshToken.RevokedOn = DateTime.UtcNow;;
            await _userManager.UpdateAsync(user);
            return true;

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
