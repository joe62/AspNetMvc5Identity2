using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;
using Users.Models;

namespace Users.Infrastructure
{
    public class AppIdentityDbContext: IdentityDbContext<AppUser>
    {
        public AppIdentityDbContext():base("IdentityDb"){}
        static  AppIdentityDbContext()
        {
            Database.SetInitializer<AppIdentityDbContext>(new IdentityDbInit());
        }
        public static AppIdentityDbContext Create()
        {
            return new AppIdentityDbContext();
        }
        public class IdentityDbInit : DropCreateDatabaseIfModelChanges<AppIdentityDbContext>
        {
            protected override void Seed(AppIdentityDbContext context)
            {
                PerformInitialSetup(context);
                base.Seed(context);
            }

            public void PerformInitialSetup(AppIdentityDbContext context)
            {
                // 在此添加初始化配置
            }
        }
    }
}