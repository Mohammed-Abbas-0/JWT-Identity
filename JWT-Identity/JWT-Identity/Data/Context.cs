using JWT_Identity.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_Identity.Data
{
    public class Context:IdentityDbContext<AppUser>
    {
        public Context(DbContextOptions options):base(options)
        {

        }
    }
}
