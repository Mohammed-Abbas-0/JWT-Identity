using JWT_Identity.Data;
using JWT_Identity.Models;
using JWT_Identity.Services;
using JWT_Project.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWT_Identity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWT_Identity", Version = "v1" });
            });

            services.AddDbContext<Context>(idx =>
                idx.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services
                .AddIdentity<AppUser, IdentityRole>()
                //يقوم بتحديد استخدام Entity Framework Core
                //كوسيط لتخزين بيانات المستخدمين والأدوار.
                //كما يحدد النوع (<Context>) الذي يمثل سياق قاعدة البيانات.
                .AddEntityFrameworkStores<Context>()
                //هذا السطر يقوم بإضافة مزودات الرموز الافتراضية لخدمة Identity.
                //تتولى هذه المزودات إنشاء وإدارة الرموز المستخدمة في
                //عمليات المصادقة مثل تأكيد البريد الإلكتروني وإعادة تعيين كلمة المرور.

                .AddDefaultTokenProviders();

            // Process To mapped between data JWT Class => JWT prop
            services.Configure<JWT>(Configuration.GetSection("JWT"));


            services.AddScoped<IAuthServices,AuthServices>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "JWT_Identity v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
