using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace Users.Infrastructure
{
    public class CustomPasswordValidator : PasswordValidator
    {
      
        public override async Task<IdentityResult> ValidateAsync(string passwd)
        {
            var result = await base.ValidateAsync(passwd);
            if (passwd.Contains("123456"))
            {
                var errors = result.Errors.ToList();
                errors.Add("密码不可包含连续的数字");
                result = new IdentityResult(errors);
            }
            return result;
        }
    }
}