# 第14章 应用ASP.NET Identity ....37
###    14.1 认证用户           ...37
###   14_2 理解认证与授权过程 ....38


通过Authorize属性标签给Action方法设置权限保护。

用户认证
======

什么是认证？
    认证就是检查用户提供的身体凭证。通过认证后，来自此浏览器的请求就包含代表此用户身份的cookie.

为什么关注？
    认证就是如何去检查你的用户身份，同时最主要的目的就是限制访问应用程序的敏感部分。 

如何在MVC框架中去使用呢？
    通过Authorize属性标签，可用于控制器和Action方法，限制没有被认证用户来访问。

### 1. 在Home控制器的Index方法上添加Authorize属性标签

```
 public class HomeController : Controller
    {
        // GET: Home
        [Authorize]
        public ActionResult Index()
        {
            var data = new Dictionary<string, object>();
            data.Add("Placeholder", "Placeholder");
            return View(data);
        }
    }

```


![](14 无权限跳转Login.png)

图示 14.1 无权限跳转Login(此时没有实现)

跳转Login是在App_Start目录下的IdentityConfig.cs中指定的如下

```
  public class IdentityConfig
    {
        public void Configuration(IAppBuilder app)
        {
            app.CreatePerOwinContext<AppIdentityDbContext>(AppIdentityDbContext.Create);
            app.CreatePerOwinContext<AppUserManager>(AppUserManager.Create);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
            });
        }
    }

```

### 2. 添加LoginModel类： 在UserViewModels.cs中增加LoginModel

```
 public class LoginModel
    {
        [Required]
        [Display(Name = "用户名称")]
        public string Name { get; set; }
        [Required]
        [Display(Name = "用户密码")]
        public string Password { get; set; }
    }

``` 

### 3.  添加Account控制器

```

 [Authorize]
    public class AccountController : Controller
    {

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            if (ModelState.IsValid) { }
            ViewBag.returnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginModel details, string returnUrl)
        {
            return View(details);
        }
    }

```

### 4.  添加Login视图

```

@model Users.Models.LoginModel
@{
    ViewBag.Title = "Login";
}

<h2>登入</h2>

@Html.ValidationSummary()
@using (Html.BeginForm())
{
    @Html.AntiForgeryToken();
    <input type="hidden" name="returnUrl" value="@ViewBag.returnUrl"/>
    <div class="form-group">
        <label>用户名称</label>
        @Html.TextBoxFor(x => x.Name, new { @class="form-control"})
    </div>
    <div class="form-group">
        <label>用户密码</label>
        @Html.PasswordFor(x => x.Password, new { @class = "form-control" })
    </div>
    <button class="btn btn-primary" type="submit">登录</button>
}



```
### 访问http://localhost:5920/ 时被转到登录视图


![](14_2 登入视图.png)                         

图示14.2 登录界面

### 5 增加Login控制器

```
namespace Users.Controllers
{
    using Microsoft.Owin.Security;
    using System.Security.Claims;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.Owin;
    [Authorize]
    public class AccountController : Controller
    {

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
             ViewBag.returnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginModel details, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindAsync(details.Name,details.Password);
                if (user==null)
                {
                    ModelState.AddModelError("", "无效用户名或密码！");
                }
                else
                {
                    var ident = await UserManager.CreateIdentityAsync(user, 
                        DefaultAuthenticationTypes.ApplicationCookie);
                    AuthManager.SignOut();
                    AuthManager.SignIn(new AuthenticationProperties
                    {
                        IsPersistent = false
                    }, ident);
                    return Redirect(returnUrl);
                }
            }
            ViewBag.returnUrl = returnUrl;
            return View(details);
        }

        [Authorize]
        public ActionResult Logout()
        {
            AuthManager.SignOut();
            return RedirectToAction("Index", "Home");
        }
        private IAuthenticationManager AuthManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private AppUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<AppUserManager>();
            }
        }
    }
}

```

![](14_3 登录并跳转到主页.png)

图示14. 3 登录并中转到主页


                    
### 14.6  用角色带给用户授权

前面是最简单的授权方式，给所有认证用户都能执行action方法。

它是什么？
    授权是允许具有角色成员资格的用户对控制器和action方法访问的过程。

我为什么关注？
    如果没有角色，你是很难分辨用户是否授权。大多数应用程序都有不同的用户类型，比如客户和管理员。

通过MVC框架该怎么使用？
    通过给Authorize标签属性强制添加角色来实现对控制器和action方法的授权。

### 14.7 添加对角色的支持

```

namespace Users.Models
{
    public class AppRole: IdentityRole
    {
        public AppRole() : base() { }
        public AppRole(string name) : base(name) { }
    }
}


namespace Users.Infrastructure
{
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Microsoft.AspNet.Identity.Owin;
    using Microsoft.Owin;

    public class AppRoleManager : RoleManager<AppRole>, IDisposable
    {
        public AppRoleManager(RoleStore<AppRole> store)
            : base(store)
        {
        }
        public static AppRoleManager Create(
        IdentityFactoryOptions<AppRoleManager> options,
        IOwinContext context)
        {
            return new AppRoleManager(new
            RoleStore<AppRole>(context.Get<AppIdentityDbContext>()));
        }
    }
}


```

### 修改IdentityConfig.cs

```
public class IdentityConfig
    {
        public void Configuration(IAppBuilder app)
        {
            app.CreatePerOwinContext<AppIdentityDbContext>(AppIdentityDbContext.Create);
            app.CreatePerOwinContext<AppUserManager>(AppUserManager.Create);
            app.CreatePerOwinContext<AppRoleManager>(AppRoleManager.Create);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
            });


        }
    }

```

### 增加角色管理控制器RoleAdmin

```
namespace Users.Controllers
{
    using Microsoft.Owin.Security;
    using System.Security.Claims;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.Owin;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
    using Users.Models;
    public class RoleAdminController : Controller
    {
        // GET: RoleAdmin
        public ActionResult Index()
        {
            return View(RoleManager.Roles);
        }

        public ActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public async Task<ActionResult> Create([Required]string name)
        {
            if (ModelState.IsValid)
            {
                var result = await RoleManager.CreateAsync(new AppRole(name));
                if (result.Succeeded)
                {
                    return RedirectToAction("Index");
                }
                else
                {
                    AddErrorsFromResult(result);
                }
            }
            return View(name);
        }
        [HttpPost]
        public async Task<ActionResult> Delete(string id)
        {
            AppRole role = await RoleManager.FindByIdAsync(id);
            if (role!=null)
            {
                var result = await RoleManager.DeleteAsync(role);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index");
                }
                else
                {
                    return View("Error", result.Errors);
                }
            }
            else
            {
                return View("Error", new string[] { "角色不存在" });
            }
        }
        private void AddErrorsFromResult(IdentityResult result)
        {
            foreach (string error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }
        private AppUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<AppUserManager>();
            }
        }

        private AppRoleManager RoleManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<AppRoleManager>();

            }
        }
    }

}

```
### 添加扩展方法获取当前用户名

```
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

```

### 添加Index.cshtml视图

```
@using Users.Models
@using Users.Infrastructure
@model IEnumerable<AppRole>
@{
    ViewBag.Title = "角色";
}

<div class="panel panel-primary" >
    <div class="panel-heading">角色</div>
    <table class="table table-striped">
        <tr><th>标识</th><th>角色名称</th><th>用户数组</th></tr>
        @if (Model.Count() == 0)
        {
            <tr><td colspan="4" class="text-center">没有角色</td></tr>
        }
        else
        {
            foreach (AppRole role in Model)
            {
                <tr>
                    <td>@role.Id</td>
                    <td>@role.Name</td>
                    <td>
                        @if (role.Users == null || role.Users.Count == 0)
                        {
                            @:角色里没有用户
                        }
                        else
                        {
                            <p>@string.Join(", ",role.Users.Select(x=>Html.GetUserName(x.UserId)))</p>
                        }
                    </td>
                    <td>
                        @using (Html.BeginForm("delete", "RoleAdmin", new { id = role.Id }))
                        {
                            @Html.ActionLink("编辑", "Edit", new { id = role.Id }, new { @class="btn btn-primary btn-xs"})
                            <button class="btn btn-danger btn-xs" type="submit">删除</button>
                        }
                    </td>
                </tr>
            }
        }
    </table>
</div>
@Html.ActionLink("添加角色", "Create", null, new { @class="btn btn-primary"})

````

![](14_4 角色管理.png)

图示14.4 角色管理


### 角色create.cshtml视图

````

@model string

@{
    ViewBag.Title = "添加角色";
}

<h2>添加角色</h2>

@Html.ValidationSummary(false)
@using (Html.BeginForm())
{
    <div class="form-group">
        <label>角色名称</label>
        <input name="name" value="@Model" class="form-control" />
    </div>
    <button type="submit" class="btn btn-primary">添加角色</button>
    @Html.ActionLink("取消","Index",null,new {@class="btn btn-default"})
}

```

![](14_5 添加角色.png)

图示14.5 添加角色create.cshtml


### 14.8 管理角色成员

在UserViewModels.cs文件中添加如下代码

```
 public class RoleEditModel
    {
        public AppRole Role { get; set; }
        public IEnumerable<AppUser> Members { get; set; }
        public IEnumerable<AppUser> NonMembers { get; set; }
    }
    public class RoleModificationModel
    {
        [Required]
        [Display(Name = "角色名称")]
        public string RoleName { get; set; }
        public string[] IdsToAdd { get; set; }
        public string[] IdsToDelete { get; set; }
    }

```

### 在RoleAdmin控制器中添加如下代码

```
     public async Task<ActionResult> Edit(string id)
        {
            var role = await RoleManager.FindByIdAsync(id);
            var memberIDs = role.Users.Select(x => x.UserId).ToArray();
            var members = UserManager.Users.Where(x => memberIDs.Any(y => y == x.Id));
            var nonMembers = UserManager.Users.Except(members);
            return View(new RoleEditModel
            {
                Role = role,
                Members=members,
                NonMembers=nonMembers
            });
        }

        [HttpPost]
        public async Task<ActionResult> Edit(RoleModificationModel model)
        {
            IdentityResult result;
            if (ModelState.IsValid)
            {
                foreach (string userId in model.IdsToAdd??new string[]{})
                {
                    result = await UserManager.AddToRoleAsync(userId, model.RoleName);
                    if (!result.Succeeded)
                    {
                        return View("Error", result.Errors);
                    }

                }
                foreach (string userId in model.IdsToDelete??new string[]{})
                {
                    result = await UserManager.RemoveFromRoleAsync(userId, model.RoleName);
                    if (!result.Succeeded)
                    {
                        return View("Error", result.Errors);
                    }
                }
                return RedirectToAction("Index");
            }
            return View("Error", new string[] { "角色没有找到" });
        }


```

### 添加角色Edit.cshtml视图

```

@using Users.Models
@model RoleEditModel
@{
    ViewBag.Title = "编辑角色";
}
@Html.ValidationSummary()
@using (Html.BeginForm())
{
    <input type="hidden" name="roleName" value="@Model.Role.Name" />
    <div class="panel panel-primary">
        <div class="panel-heading">添加到 @Model.Role.Name</div>
        <table class="table table-striped">
            @if (Model.NonMembers.Count() == 0)
            {
                <tr><td colspan="2">所有用户都是成员</td></tr>
            }
            else
            {
                <tr><td>用户标识</td><td>添加到角色</td></tr>
                foreach (AppUser user in Model.NonMembers)
                {
                    <tr>
                        <td>@user.UserName</td>
                        <td><input type="checkbox" name="IdsToAdd" value="@user.Id" /></td>
                    </tr>
                }
            }

        </table>
    </div>
    <div class="panel panel-primary">
        <div class="panel-heading">从 @Model.Role.Name 中删除</div>
        <table class="table table-striped">
            @if (Model.Members.Count()==0)
            {
                <tr><td colspan="2">没有成员用户</td></tr>

            }
            else
            {
                <tr><td>用户标识</td><td>从角色中删除</td></tr>
                foreach (AppUser user in Model.Members)
                {
                    <tr>
                        <td>@user.UserName</td>
                        <td><input type="checkbox" name="IdsToDelete" value="@user.Id" /></td>
                    </tr>
                }
            }
        </table>
    </div>
    <button type="submit" class="btn btn-primary">保存</button>
    @Html.ActionLink("取消", "Index", null, new { @class="btn btn-default"})
}

```


![](14_6 角色成员编辑.png)

图示14.6 角色成员编辑endit.cshtml


Name                     Email                                Password
Alice             alice@example.com                 MySecret
Bob               bob@example.com                  MySecret
Joe                joe@example.com                    MySecret

### 14.9  用户角色授权

修改Home控制器如下：

```
      [Authorize(Roles="Users")]
        public ActionResult OtherAction()
        {
            return View("Index", GetData("OtherAction"));
        }

```
修改Account控制器如下：


```

    [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return View("Error", new string[] { "访问拒绝" });
            }

             ViewBag.returnUrl = returnUrl;
            return View();
        }

```

## Seeding the Database    ..................................  p64

在Entity Framework设置类(AppIdentityDbContext.cs - IdentityDbInit类 -> PerformInitialSetup函数)中植入创建初始用户和角色的程序。如下代码所示：

```
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

```
增加了上述代码后，就可以对Admin和RoleAdmin控制器增加Authorize属性了

![](14_7 数据库表结构IndenityDb.png)

图14.7 数据库表结构IndenityDb

删除数据库IndentityDb，新建一个空的数据库。http://localhost:5920/ 



此时输入默认的管理员用户Admin，密码MySecret，系统自动创建数据的Schema，并自动添加默认管理员用户。



