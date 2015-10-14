# ASP.NET Identity笔记


目录
第14章 应用ASP.NET Identity   ....................................37
       14.1节  认证用户.......................................................37
        14.2节    理解认证与授权的过程 ..............................38


1. 准备示例项目
=============

创建空MVC项目




安装bootstrap 

PM>Install-Package bootstrap

添加Home控制器

```
   public class HomeController : Controller
    {
        // GET: Home
        public ActionResult Index()
        {
            var data = new Dictionary<string, object>();
            data.Add("Placeholder", "Placeholder");
            return View(data);
        }
    }
```
添加视图Home的Index的视图
```
@{
    ViewBag.Title = "Index";
}
<div class="panel panel-primary">
    <div class="panel-heading">用户信息</div>
    <table class="table table-striped">
        @foreach (string key in Model.Keys) { 
            <tr>
                <th>@key</th>
                <td>@Model[key]</td>
            </tr>
        }
    </table>
</div>
```
修改视图模板Views/Shared/_Layout.cshtml

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>@ViewBag.Title</title>
    <link href="~/Content/bootstrap.min.css" rel="stylesheet" type="text/css" />
    <link href="~/Content/bootstrap-theme.min.css" rel="stylesheet" />
    <style>
        .container{padding:10px;}
        .validation-summary-errors{color:#f00;}
    </style>
</head>
<body class="container">
    <div class="container">
        @RenderBody()
    </div>
</body>
</html>

运行项目



2. 安装配置ASP.NET Identity
=====================
安装相关库

    PM> Install-Package Microsoft.AspNet.Identity.EntityFramework -Version 2.2.1
        Microsoft.AspNet.Identity.Core 2.2.1
        EntityFramework 6.1.0
        Microsoft.AspNet.Identity.EntityFramework 2.2.1
        Microsoft.AspNet.Identity.Core 2.2.1

    PM> Install-Package Microsoft.AspNet.Identity.OWIN
             Owin 1.0
            Microsoft.Owin 2.1.0
            Microsoft.Owin.Security 2.1.0
            Microsoft.Owin.Security.Cookies 2.1.0
            Newtonsoft.Json 4.5.11
            Microsoft.Owin.Security.OAuth 2.1.0
            Microsoft.AspNet.Identity.Owin 2.2.1

    PM> Install-Package Microsoft.Owin.Host.SystemWeb
            Microsoft.Owin.Host.SystemWeb 3.0.1
            Microsoft.Owin 3.0.1
            卸载“Microsoft.Owin 2.1.0”

配置Web.config

```
<connectionStrings>
    <add name="IdentityDb"
nectionString="Data Source=(LocalDB)\v11.0;Initial Catalog=IdentityDb.mdf;Integrated Security=True;Connect Timeout=30 Encrypt=False;TrustServerCertificate=False;MultipleActiveResultSets=True"
      providerName="System.Data.SqlClient" />
  </connectionStrings>

 <add key="owin.AppStartup" value="Users.IdentityConfig"/>
  </appSettings>

```

在Moduls目录新增AppUserModels.cs文件

AppUser类
```
    public class AppUser: IdentityUser
    {
    }
```

在infrastructure目录增加AppIdenityDbContext.cs

```
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
```

创建用户管理类
在Infrastructure目录添加AppUserManager.cs

```
namespace Users.Infrastructure
{
    public class AppUserManager: UserManager<AppUser>
    {
        public AppUserManager(IUserStore<AppUser> store):base(store){}
        public static AppUserManager Create(IdentityFactoryOptions<AppUserManager> options,IOwinContext context){
            AppIdentityDbContext db = context.Get<AppIdentityDbContext>();
            AppUserManager manager = new AppUserManager(new UserStore<AppUser>(db));
            return manager;
        }
    }
}
```

创建启动类

在App_Start目录添加IdenfityConfig.cs
```
namespace Users
{
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
}
```

3. 使用Idenfity  p15 ***
====================
添加Admin控制器
```
using Microsoft.AspNet.Identity.Owin;
namespace Users.Controllers
{
 Enumerating User Accounts ----------- P15
    public class AdminController : Controller
    {
        // GET: Admin
        public ActionResult Index()
        {
            return View(UserManager.Users);
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
添加Admin控制器的Index的视图

```
@using Users.Models
@model IEnumerable<AppUser>
@{ViewBag.Title = "Index";}
<div class="panel panel-primary">
    <div class="panel-heading">
        用户账号列表
    </div>
    <table class="table table-striped">
        <tr><th>标识</th><th>用户名</th><th>邮箱</th></tr>
        @if (Model.Count() == 0){
            <tr><td colspan="3" class="text-center">账号为空</td></tr>
        }else{
            foreach (AppUser user in Model){
                <tr>
                    <td>@user.Id</td>
                    <td>@user.UserName</td>
                    <td>@user.Email</td>
                </tr>
            }
        }
    </table>
</div>
@Html.ActionLink("新建", "Create", null, new { @class = "btn btn-primary" })
```

运行



增加创建用户模型
Model文件夹：
```
 public class CreateModel
    {
        [Required]
        [Display(Name="用户名")]
        public string Name { get; set; }
        [Required]
        [Display(Name="电子邮件")]
        public string Email { get; set; }
        [Required]
        [Display(Name="用户密码")]
        public string Password { get; set; }
    }
```

在Admin控制器中添加Create方法 - 创建用户
```
       public ActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public async Task<ActionResult> Create(CreateModel model)
        {
            if (ModelState.IsValid)
            {
                AppUser user = new AppUser { UserName = model.Name, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index");
                }
                else
                {
                    AddErrorsFromResult(result);
                }
            }
            return View(model);
        }
        private void AddErrorsFromResult(IdentityResult result)
        {
            foreach (string error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }
```
添加用户表单 Create.cshtml

```
@model Users.Models.CreateModel
@{ViewBag.Title = "新建用户";}          
<h2>@ViewBag.Title</h2>
@Html.ValidationSummary(false)
@using (Html.BeginForm())
{
    <div class="form-group">
        <label>用户姓名</label>
        @Html.TextBoxFor(x => x.Name, new { @class="form-control"})
    </div>
    <div class="form-group">
        <label>电子邮件</label>
        @Html.TextBoxFor(x => x.Email, new { @class="form-control"})
    </div>
    <div class="form-group">
        <label>用户密码</label>
        @Html.PasswordFor(x => x.Password, new { @class="form-control"})
    </div>
    <button type="submit" class="btn btn-primary">添加用户</button>
    @Html.ActionLink("取消", "Index", null, new { @class="btn btn-default"})
}
```

运行 admin/create/

输入








验证密码

### PasswordValidator类的属性：

1. RequiredLength - 指定有效密码的最小长度
2. RequireNonLetterOrDigit - 为true, 则密码必须包含符号（非字母，或数字）
3. RequireDigit - 为true,  则密码必须包含数字
4. RequireLowercase - 为true,  则密码必须包含小写字母
5. RequireUppercase - 为true,  则密码必须包含大写字母

```
  public class AppUserManager: UserManager<AppUser>
    {
        public AppUserManager(IUserStore<AppUser> store):base(store){}
        public static AppUserManager Create(IdentityFactoryOptions<AppUserManager> options,IOwinContext context)
        {
            var db = context.Get<AppIdentityDbContext>();
            var manager = new AppUserManager(new UserStore<AppUser>(db));
            // 6位包含大小写字母
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit=false,
                RequireDigit=false,
                RequireLowercase=true,
                RequireUppercase=true
            };
            return manager;
        }
    }
```



实现自定义密码验证

```
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

修改AppUserManager->Create

   public class AppUserManager: UserManager<AppUser>
    {
        public AppUserManager(IUserStore<AppUser> store):base(store){}
        public static AppUserManager Create(IdentityFactoryOptions<AppUserManager> options,IOwinContext context)
        {
            var db = context.Get<AppIdentityDbContext>();
            var manager = new AppUserManager(new UserStore<AppUser>(db));
            // 6位包含大小写字母
            manager.PasswordValidator = new CustomPasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit=false,
                RequireDigit=false,
                RequireLowercase=true,
                RequireUppercase=true
            };
            return manager;
        }
    }

```



验证用户名

UserValidator类：
1. AllowOnlyAlphanumericUserNames - 为true时， 用户名只能包含字母和数字。
2. RequireUniqueEmail - 为true时，只能用电子邮件地址。

```
在manager.PasswordValidator = new CustomPasswordValidator之后添加

         // 用户名必须同时包含字母和数字
            manager.UserValidator = new UserValidator<AppUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = true,
                RequireUniqueEmail = true
            };
```



自定义用户验证类重新UserValidator

```
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
                errors.Add("只有example.com邮件地址为有效邮件地址");
                result = new IdentityResult(errors);
            }

            return result;
        }
    }
}

 // 用户名必须同时包含字母和数字
            manager.UserValidator = new CustomUserValidator(manager)
            {
                AllowOnlyAlphanumericUserNames = true,
                RequireUniqueEmail = true
            };

```




增加编辑和删除功能

```
@using Users.Models
@model IEnumerable<AppUser>
@{ViewBag.Title = "Index";}
<div class="panel panel-primary">
    <div class="panel-heading">
        已注册用户
    </div>
    <table class="table table-striped">
        <tr><th>标识</th><th>用户名称</th><th>用户邮箱</th></tr>
        @if (Model.Count() == 0){
            <tr><td colspan="4" class="text-center">无注册用户</td></tr>
        }else{
            foreach (AppUser user in Model){
                <tr>
                    <td>@user.Id</td>
                    <td>@user.UserName</td>
                    <td>@user.Email</td>
                    <td>
                        @using (Html.BeginForm("Delete", "Admin", new { id = user.Id }))
                        {
                            @Html.ActionLink("编辑", "Edit", new { id=user.Id},new{@class="btn btn-primary btn-xs"})
                            <button class="btn btn-danger btn-xs" type="submit">删除</button>
                        }
                    </td>
                </tr>
            }
        }
    </table>
</div>
@Html.ActionLink("新建", "Create", null, new { @class = "btn btn-primary" })

 [HttpPost]
        public async Task<ActionResult> Delete(string id)
        {
            var user = await UserManager.FindByIdAsync(id);
            if (user!=null)
            {
                var result = await UserManager.DeleteAsync(user);
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
                return View("Error", new string[] { "User Not Found" });
            }

        }


       public async Task<ActionResult> Edit(string id)
        {
            var user = await UserManager.FindByIdAsync(id);
            if (user != null)
            {
                return View(user);
            }
            else
            {
                return RedirectToAction("Index");
            }
        }
        [HttpPost]
        public async Task<ActionResult> Edit(string id, string email, string password)
        {
            var user = await UserManager.FindByIdAsync(id);
            if (user != null)
            {
                user.Email = email;
                var validEmail = await UserManager.UserValidator.ValidateAsync(user);
                if (!validEmail.Succeeded)
                {
                    AddErrorsFromResult(validEmail);
                }
                IdentityResult validPass = null;
                if (password != string.Empty)
                {
                    validPass = await UserManager.PasswordValidator.ValidateAsync(password);
                    if (validPass.Succeeded)
                    {
                        user.PasswordHash = UserManager.PasswordHasher.HashPassword(password);
                    }
                    else
                    {
                        AddErrorsFromResult(validPass);
                    }
                }
                if((validEmail.Succeeded && validPass==null)||
                    (validEmail.Succeeded && password != string.Empty && validPass.Succeeded))
                {
                    var result = await UserManager.UpdateAsync(user);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index");
                    }
                    else
                    {
                        AddErrorsFromResult(result);
                    }
                }
            }
            else
            {
                ModelState.AddModelError("", "User Not Found");
            }
            return View(user);
        }

Edit.cshtml

@model Users.Models.AppUser
@{ViewBag.Title = "编辑用户信息";}           
@Html.ValidationSummary(false)
<h2>编辑用户信息</h2>
<div class="form-group">
    <label>用户名</label>
    <p class="form-control-static">@Model.UserName</p>
</div>
@using (Html.BeginForm())
{
    @Html.HiddenFor(x=>x.Id)
    <div class="form-group">
        <label>电子邮件</label>
        @Html.TextBoxFor(x => x.Email, new {@class="form-control"})
    </div>
    <div class="form-group">
        <label>用户密码</label>
        <input name="password" type="password" class="form-control" />
    </div>
    <button type="submit" class="btn btn-primary ">保存</button>
    @Html.ActionLink("Cancel", "Index", null, new { @class="btn btn-default"})
}

```




第14章 应用ASP.NET Identity      ............................................37
           用户账号认证与授权，角色授权
    14.1 认证用户................................................................................................37
    14.2 理解认证与授权过程   ........................................................................38
通过Authorize属性标签给Action方法设置权限保护。

参考
OWIN - Open Web Interface Katana是微软对此的具体实现。
《Expert ASP.NET Web API 2 for MVC Developers》


Now that the basic setup is out of the way, I can start to use ASP.NET Identity to add support for managing users to the example applicaiton.
至此基本设置已完成，在这个例子中，我现在可以用ASP.NET Identity来添加对用户管理的支持了。
Centralized user administration tools 
集中式用户管理工具




