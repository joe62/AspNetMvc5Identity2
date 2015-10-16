using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Users.Infrastructure
{
    using Microsoft.AspNet.Identity.Owin;
    using System.Web.Mvc;
    public static class IdentityHelpers
    {
        public static MvcHtmlString GetUserName(this HtmlHelper html, string id)
        {
            var mgr = HttpContext.Current.GetOwinContext().GetUserManager<AppUserManager>();
            return new MvcHtmlString(mgr.FindByIdAsync(id).Result.UserName);
        }
    }
}