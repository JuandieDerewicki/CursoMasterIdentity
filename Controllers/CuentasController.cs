﻿using CursoIdentityUdemy.Models;
using CursoIdentityUdemy.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace CursoIdentityUdemy.Controllers
{
    [Authorize]
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;
        public readonly UrlEncoder _urlEncoder;

        public CuentasController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender, UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
            _roleManager = roleManager;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Registro(string returnurl = null)
        {
            // Para la creacion de los roles
            if(!await _roleManager.RoleExistsAsync("Administrador"))
            {
                // Creacion de rol usuario administrador
                await _roleManager.CreateAsync(new IdentityRole("Administrador"));
            }
            if (!await _roleManager.RoleExistsAsync("Registrado"))
            {
                // Creacion de rol usuario administrador
                await _roleManager.CreateAsync(new IdentityRole("Registrado"));
            }


            ViewData["Returnurl"] = returnurl;
            RegistrerViewModel registroVM = new RegistrerViewModel();
            return View(registroVM);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Registro(RegistrerViewModel rgViewModel, string returnurl = null)
        {
            ViewData["Returnurl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/"); // Si no tiene ningun returnurl va al incio

            // Validamos el modelo osea los datos que ponga en el registro
            if (ModelState.IsValid)
            {
                var usuario = new AppUsuario { UserName = rgViewModel.Email, Email = rgViewModel.Email, Nombre = rgViewModel.Nombre, Url = rgViewModel.Url, CodigoPais = rgViewModel.CodigoPais, Telefono = rgViewModel.Telefono, Pais = rgViewModel.Pais, Ciudad = rgViewModel.Ciudad, Direccion = rgViewModel.Direccion, FechaNacimiento = rgViewModel.FechaNacimiento, Estado = rgViewModel.Estado };
                var resultado = await _userManager.CreateAsync(usuario, rgViewModel.Password); // con esto dos ya crea el usuario

                if (resultado.Succeeded)
                {
                    // Asignacion del usuario que se registra al rol
                    await _userManager.AddToRoleAsync(usuario, "Registrado");
                    //Implementacion de confirmacion de email en el registro
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(usuario);
                    var urlRetorno = Url.Action("ConfirmarEmail", "Cuentas", new { userId = usuario.Id, code = code }, protocol: HttpContext.Request.Scheme);
                    await _emailSender.SendEmailAsync(rgViewModel.Email, "Confirmar su cuenta - Proyecto Identity", "Por favor confirme su cuenta dando click aquí: <a href=\"" + urlRetorno + "\">enlace</a>");
                    // La persona quede autenticada dentro de la aplicacion
                    await _signInManager.SignInAsync(usuario, isPersistent: false);
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnurl); // Para que estén protegidos y no vulneren la aplicacion
                }
                ValidarErrores(resultado);
            }
            return View(rgViewModel);
        }

        // Registro especial para solo los administradores
        [HttpGet]
        public async Task<IActionResult> RegistroAdministrador(string returnurl = null)
        {
            if (!await _roleManager.RoleExistsAsync("Administrador"))
            {
                await _roleManager.CreateAsync(new IdentityRole("Administrador"));
            }
            if (!await _roleManager.RoleExistsAsync("Registrado"))
            {
                await _roleManager.CreateAsync(new IdentityRole("Registrado"));
            }
            List<SelectListItem> listaRoles = new List<SelectListItem>();
            listaRoles.Add(new SelectListItem
            {
                Value = "Registrado",
                Text = "Registrado"
            });
            listaRoles.Add(new SelectListItem
            {
                Value = "Administrador",
                Text = "Administrador"
            });


            RegistrerViewModel registroVm = new RegistrerViewModel()
            {

                ListaRoles = (IEnumerable<SelectList>)listaRoles

            };
            ViewData["ReturnUrl"] = returnurl;

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegistroAdministrador(RegistrerViewModel vmRegistro, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {

                var app_new_Usuari = new AppUsuario() { UserName = vmRegistro.Email, Nombre = vmRegistro.Nombre, Email = vmRegistro.Email, Ciudad = vmRegistro.Ciudad, CodigoPais = vmRegistro.CodigoPais, Pais = vmRegistro.Pais, Url = vmRegistro.Url, Direccion = vmRegistro.Direccion, FechaNacimiento = vmRegistro.FechaNacimiento, Estado = vmRegistro.Estado };
                var resultado = await _userManager.CreateAsync(app_new_Usuari, vmRegistro.Password);

                if (resultado.Succeeded)
                {
                    if (vmRegistro.RolSeleccionado != null && vmRegistro.RolSeleccionado.Length > 0 && vmRegistro.RolSeleccionado == "Administrador")
                    {
                        await _userManager.AddToRoleAsync(app_new_Usuari, "Administrador");
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(app_new_Usuari, "Registrado");
                    }

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(app_new_Usuari);
                    var urlRetorno = Url.Action("ConfirmarEmail", "Cuentas", new { UserId = app_new_Usuari.Id, code = code }, protocol: HttpContext.Request.Scheme);

                    await _signInManager.SignInAsync(app_new_Usuari, isPersistent: false);

                    await _emailSender.SendEmailAsync(vmRegistro.Email, "Confirmar su cuenta - Proyecto Identity", "Por favor confirme su contraseña dando click aqui <a href=\"" + urlRetorno + "\">enlace</a>");
                    return LocalRedirect(returnurl);
                }
                else { ValidarErrores(resultado); }
            }

            List<SelectListItem> listaRoles = new List<SelectListItem>();
            listaRoles.Add(new SelectListItem
            {
                Value = "Registrado",
                Text = "Registrado"
            });
            listaRoles.Add(new SelectListItem
            {
                Value = "Administrador",
                Text = "Administrador"
            });

            vmRegistro.ListaRoles = (IEnumerable<SelectList>)listaRoles;
            return View(vmRegistro);
        }

        // Manejo de errores
        [AllowAnonymous]
        private void ValidarErrores(IdentityResult resultado)
        {
            foreach (var error in resultado.Errors)
            {
                ModelState.AddModelError(String.Empty, error.Description);
            }
        }

        // Metodo mostrar formulario de acceso
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Acceso(string returnurl = null)
        {
            ViewData["Returnurl"] = returnurl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Acceso(LoginViewModel accViewModel, string returnurl = null)
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
                // Para autenticacion de dos factores
                if (resultado.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerificarCodigoAutenticador), new { returnurl, accViewModel.RememberMe });
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
        [AllowAnonymous]
        public IActionResult OlvidoPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> OlvidoPassword(OlvidoPasswordViewModel opViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _userManager.FindByEmailAsync(opViewModel.Email); // le mandamos el email para que lo encuentre
                if (usuario == null)
                {
                    return RedirectToAction("ConfirmacionOlvidoPassword");
                }
                var codigo = await _userManager.GeneratePasswordResetTokenAsync(usuario);
                var urlRetorno = Url.Action("ResetPassword", "Cuentas", new { userId = usuario.Id, code = codigo }, protocol: HttpContext.Request.Scheme);

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

        // Funcionalidad para recuperar contraseña
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View(); // Si viene codigo osea que no es null, osea que viene token retorna a la vista normal y si no a la vista error
        }

        [HttpPost]
        [ValidateAntiForgeryToken] // Para proteger las peticiones HTTPOST
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(RecuperaPasswordViewModel rpViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _userManager.FindByEmailAsync(rpViewModel.Email); // le mandamos el email para que lo encuentre
                if (usuario == null)
                {
                    return RedirectToAction("ConfirmacionRecuperaPassword");
                }

                var resultado = await _userManager.ResetPasswordAsync(usuario, rpViewModel.Code, rpViewModel.Password);
                if (resultado.Succeeded)
                {
                    return RedirectToAction("ConfirmacionRecuperaPassword");
                }

                ValidarErrores(resultado);
            }
            return View(rpViewModel); // normal y si no a la vista error
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmacionRecuperaPassword()
        {
            return View();
        }


        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmarEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }

            var usuario = await _userManager.FindByIdAsync(userId);  // Obtenemos el usuario

            if (usuario == null) // Valido si existe en la bd 
            {
                return View("Error");
            }

            var resultado = await _userManager.ConfirmEmailAsync(usuario, code);
            return View(resultado.Succeeded ? "ConfirmarEmail" : "Error");
        }


        // Configuracion de acceso externo: facebook, google, twitter, etc
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult AccesoExterno(string proveedor, string returnurl = null)
        {
            var urlRedireccion = Url.Action("AccesoExternoCallback", "Cuentas", new { ReturnUrl = returnurl });
            var propiedades = _signInManager.ConfigureExternalAuthenticationProperties(proveedor, urlRedireccion);
            return Challenge(propiedades, proveedor);
        }

        [HttpGet]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AccesoExternoCallback(string returnurl = null, string error = null)
        {
            returnurl = returnurl ?? Url.Content("~/"); // Si no tiene ningun returnurl va al incio
            if (error != null)
            {
                ModelState.AddModelError(string.Empty, $"Error en el acceso externo {error}");
                return View(nameof(Acceso));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Acceso));
            }

            // Acceder con el usuario en el proveedor externo 
            var resultado = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (resultado.Succeeded)
            {
                // Actualizar tokens de acceso
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnurl);
            }

            // Para autenticacion de dos factores
            if(resultado.RequiresTwoFactor)
            {
                return RedirectToAction("VerificarCodigoAutenticador", new { returnurl = returnurl });
            }
            else
            {
                // Si el usuario no tiene cuenta pregunta si quiere crear una
                ViewData["ReturnUrl"] = returnurl;
                ViewData["NombreMostrarProveedor"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var nombre = info.Principal.FindFirstValue(ClaimTypes.Name);
                return View("ConfirmacionAccesoExterno", new ConfirmacionAccesoExternoViewModel { Email = email, Name = nombre });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmacionAccesoExterno(ConfirmacionAccesoExternoViewModel caeViewModel, string returnurl = null)
        {
            returnurl = returnurl ?? Url.Content("~/"); // Si no tiene ningun returnurl va al incio

            if (ModelState.IsValid)
            {
                // Obtener la informacion del usuario del proveedor externo
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("Error");
                }

                var usuario = new AppUsuario { UserName = caeViewModel.Email, Email = caeViewModel.Email, Nombre = caeViewModel.Name };
                var resultado = await _userManager.CreateAsync(usuario);
                if (resultado.Succeeded)
                {
                    resultado = await _userManager.AddLoginAsync(usuario, info);
                    if (resultado.Succeeded)
                    {
                        await _signInManager.SignInAsync(usuario, isPersistent: false);
                        await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                        return LocalRedirect(returnurl);
                    }
                }
                ValidarErrores(resultado);
            }
            ViewData["ReturnUrl"] = returnurl;
            return View(caeViewModel);
        }

        // Autenticacion de dos factores
        [HttpGet]
        public async Task<IActionResult> ActivarAutenticador()
        {
            string formatoUrlAutenticador = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            var usuario = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(usuario);
            var token = await _userManager.GetAuthenticatorKeyAsync(usuario);

            // Habilitar codigo QR
            string urlAutenticador = string.Format(formatoUrlAutenticador, _urlEncoder.Encode("ProyectoIdentity"), _urlEncoder.Encode(usuario.Email), token);
            var adfModel = new AutenticacionDosFactoresViewModel() { Token = token, UrlCodigoQr = urlAutenticador };
            return View(adfModel);
        }

        [HttpGet]
        public async Task<IActionResult> EliminarAutenticador()
        {
            var usuario = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(usuario);
            await _userManager.SetTwoFactorEnabledAsync(usuario, false);
   
            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpPost]
        public async Task<IActionResult> ActivarAutenticador(AutenticacionDosFactoresViewModel adfViewModel)
        {
            if(ModelState.IsValid)
            {
                var usuario = await _userManager.GetUserAsync(User);
                var succeed = await _userManager.VerifyTwoFactorTokenAsync(usuario, _userManager.Options.Tokens.AuthenticatorTokenProvider, adfViewModel.Code);
                if(succeed)
                {
                    await _userManager.SetTwoFactorEnabledAsync(usuario, true);
                }
                else
                {
                    ModelState.AddModelError("Error", "Su autenticación de dos factores no ha sido validada");
                    return View(adfViewModel);
                }
            }
            return RedirectToAction(nameof(ConfirmacionAutenticador));
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmacionAutenticador()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerificarCodigoAutenticador(bool recordarDatos, string returnurl = null)
        {
            var usuario = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if(usuario == null)
            {
                return View("Error");   
            }
            ViewData["ReturnUrl"] = returnurl;
            return View(new VerificarAutenticadorViewModel { ReturnUrl = returnurl, RecordarDatos = recordarDatos });   
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> VerificarCodigoAutenticador(VerificarAutenticadorViewModel vaViewModel)
        {
            vaViewModel.ReturnUrl = vaViewModel.ReturnUrl ?? Url.Content("~/");
            if(!ModelState.IsValid)
            {
                return View(vaViewModel);
            }
            var resultado = await _signInManager.TwoFactorAuthenticatorSignInAsync(vaViewModel.Code, vaViewModel.RecordarDatos, rememberClient: false); // el remememberClient es importante cambiar si queremos que no haga siempre la autenticacion de dos factores
            if(resultado.Succeeded)
            {
                return LocalRedirect(vaViewModel.ReturnUrl);
            }
            if (resultado.IsLockedOut)
            {
                return View("Bloqueado");
            }
            else
            {
                ModelState.AddModelError(String.Empty, "Código Inválido");
                return View(vaViewModel);
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Denegado(string returnurl = null)
        {
            ViewData["Returnurl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            return View();
        }

    }
}
