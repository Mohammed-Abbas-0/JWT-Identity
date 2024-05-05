using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_Identity.Models
{
    public class TokenRequestModel
    {
        [Required]
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
