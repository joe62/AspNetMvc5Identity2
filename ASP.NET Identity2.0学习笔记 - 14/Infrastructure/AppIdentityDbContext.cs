﻿using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;
using Users.Models;

namespace Users.Infrastructure
{
    using Microsoft.AspNet.Identity;
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
                var userMgr = new AppUserManager(new UserStore<AppUser>(context));
                var roleMgr = new AppRoleManager(new RoleStore<AppRole>(context));

                string roleName = "Administrators";
                string userName = "Admin";
                string password = "MySecret";
                string email = "admin@example.com";

                if (!roleMgr.RoleExists(roleName))
                {
                    roleMgr.Create(new AppRole(roleName));
                }

                AppUser user = userMgr.FindByName(userName);
                if (user==null)
                {
                    userMgr.Create(new AppUser { UserName = userName, Email = email }, password);
                    user = userMgr.FindByName(userName);
                }

                if (!userMgr.IsInRole(user.Id, roleName))
                {
                    userMgr.AddToRole(user.Id, roleName);
                }

            }
        }
    }
}