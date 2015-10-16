using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Users.Models;

namespace Users.Infrastructure
{
    public class CustomUserValidator: UserValidator<AppUser>
    {
        public CustomUserValidator(AppUserManager mgr):base(mgr){}
        public override async Task<IdentityResult> ValidateAsync(AppUser user)
        {
            var result=await base.ValidateAsync(user);

            if (!user.Email.ToLower().EndsWith("@example.com"))
            {
                var errors = result.Errors.ToList();
                errors.Add("只能用example.com邮件地址");
                result = new IdentityResult(errors);
            }

            return result;
        }
    }
}