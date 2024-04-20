using JWT_Identity.Models;
using JWT_Project.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_Identity.Services
{
    public interface IAuthServices
    {
        Task<AuthModel> Register(RegisterModel register);
    }
}
