using CursoIdentityUdemy.Datos;
using CursoIdentityUdemy.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;


var builder = WebApplication.CreateBuilder(args);

// Configuramos la conexion a SQL Server
builder.Services.AddDbContext<ApplicationDbContext>(opciones => opciones.UseSqlServer(builder.Configuration.GetConnectionString("ConnectionSql")));

// Agregar el servicio Identity a la aplicacion como dependencia
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

// Url de retorno al acceder
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = new PathString("/Cuentas/Acceso");
    options.AccessDeniedPath = new PathString("/Cuentas/Denegado");
});

// Opciones de configuracion del identity
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 5;
    options.Password.RequireLowercase = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 3;
});

// Agregar autenticacion de facebook 
builder.Services.AddAuthentication().AddFacebook(options =>
{
    options.AppId = "1431446134416837";
    options.AppSecret = "219d65fb4e501b3bf8f7cad0f0611544"; 
});

// Agregar autenticacion de google 
//builder.Services.AddAuthentication().AddGoogle(options =>
//{
//    options.ClientId = ""; // BUSCAR CON GOOGLE CLOUD
//    options.ClientSecret = ""; // BUSCAR CON GOOGLE CLOUD
//});

// Soporte para autorizacion basada en directivas/Policy 
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Administrador", policy => policy.RequireRole("Administrador"));
    options.AddPolicy("Registrado", policy => policy.RequireRole("Registrado"));
    options.AddPolicy("Usuario", policy => policy.RequireRole("Usuario"));
    options.AddPolicy("UsuarioYAdministrador", policy => policy.RequireRole("Administrador").RequireRole("Usuario"));
    // Uso de claims
    options.AddPolicy("AdministradorCrear", policy => policy.RequireRole("Administrador").RequireClaim("Crear", "True"));
    options.AddPolicy("AdministradorEditarBorrar", policy => policy.RequireRole("Administrador").RequireClaim("Editar", "True").RequireClaim("Borrar", "True");
    options.AddPolicy("AdministradorCrearEditarBorrar", policy => policy.RequireRole("Administrador").RequireClaim("Crear", "True").RequireClaim("Editar", "True").RequireClaim("Borrar", "True"));
});

// Se agrega IEmailSender
builder.Services.AddTransient<IEmailSender, MailSender>();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Agregamos la autenticacion
app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
