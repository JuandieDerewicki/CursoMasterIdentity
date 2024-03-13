using CursoIdentityUdemy.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace CursoIdentityUdemy.Controllers
{
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;

        public CuentasController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender; 
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Registro(string returnurl = null)
        {
            ViewData["Returnurl"] = returnurl;
            RegistrerViewModel registroVM = new RegistrerViewModel();
            return View(registroVM);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Registro(RegistrerViewModel rgViewModel, string returnurl = null)
        {
            ViewData["Returnurl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/"); // Si no tiene ningun returnurl va al incio

            // Validamos el modelo osea los datos que ponga en el registro
            if (ModelState.IsValid)
            {
                var usuario = new AppUsuario { UserName = rgViewModel.Email, Email = rgViewModel.Email, Nombre = rgViewModel.Nombre, Url = rgViewModel.Url, CodigoPais = rgViewModel.CodigoPais, Telefono = rgViewModel.Telefono, Pais = rgViewModel.Pais, Ciudad = rgViewModel.Ciudad, Direccion = rgViewModel.Direccion, FechaNacimiento = rgViewModel.FechaNacimiento, Estado = rgViewModel.Estado };
                var resultado = await _userManager.CreateAsync(usuario, rgViewModel.Password); // con esto dos ya crea el usuario

                if(resultado.Succeeded)
                {
                    // La persona quede autenticada dentro de la aplicacion
                    await _signInManager.SignInAsync(usuario, isPersistent: false);
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnurl); // Para que estén protegidos y no vulneren la aplicacion
                }
                ValidarErrores(resultado);
            }
            return View(rgViewModel);
        }

        private void ValidarErrores(IdentityResult resultado)
        {
            foreach (var error in resultado.Errors)
            {
                ModelState.AddModelError(String.Empty, error.Description);
            }
        }

        // Metodo mostrar formulario de acceso
        [HttpGet]
        public IActionResult Acceso(string returnurl=null)
        {
            ViewData["Returnurl"] = returnurl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Acceso(LoginViewModel accViewModel, string returnurl=null)
        {
            ViewData["Returnurl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/"); // Si no tiene ningun returnurl va al incio
            // Validamos el modelo osea los datos que ponga en el registro
            if (ModelState.IsValid)
            {
                var resultado = await _signInManager.PasswordSignInAsync(accViewModel.Email, accViewModel.Password, accViewModel.RememberMe, lockoutOnFailure: true); 

                if (resultado.Succeeded)
                {
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnurl);
                }
                if (resultado.IsLockedOut)
                {
                    return View("Bloqueado");
                }
                else
                {
                    ModelState.AddModelError(String.Empty, "Acceso inválido");
                    return View(accViewModel);
                }
            }
            return View(accViewModel);
        }

        // Salir o cerrar sesión de la aplicacion (logout)
        [HttpPost]
        [ValidateAntiForgeryToken] // Para evitar en nuestros formularios los ataques XXS
        public async Task<IActionResult> SalirAplicacion()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home"); // Una vez se salga de la aplicacion, va a buscar el index en el home. Se sale de la aplicacion con el metodo signoutasync, destruyo las cookies del navegador, cierra la sesion y redirecciona al home
        }

        // Metodo para olvido de contraseña 
        [HttpGet]
        public IActionResult OlvidoPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OlvidoPassword(OlvidoPasswordViewModel opViewModel)
        {
            if(ModelState.IsValid)
            {
                var usuario = await _userManager.FindByEmailAsync(opViewModel.Email); // le mandamos el email para que lo encuentre
                if(usuario == null)
                {
                    return RedirectToAction("ConfirmacionOlvidoPassword"); 
                }
                var codigo = await _userManager.GeneratePasswordResetTokenAsync(usuario);
                var urlRetorno = Url.Action("ResetPassword", "Cuentas", new { userId = usuario.Id, code = codigo}, protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(opViewModel.Email, "Recuperar contraseña - Proyecto Identity", "Por favor recupere su contraseña dando click aquí: <a href=\"" + urlRetorno + "\">enlace</a>");

                return RedirectToAction("ConfirmacionOlvidoPassword");
            }
            return View(opViewModel);   
        }

        [HttpGet]
        [AllowAnonymous] // HACE PARTE DE LA AUTORIZACION
        public IActionResult ConfirmacionOlvidoPassword()
        {
            return View();  
        }

    }
}
