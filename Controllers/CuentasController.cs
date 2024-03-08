using CursoIdentityUdemy.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CursoIdentityUdemy.Controllers
{
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public CuentasController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Registro()
        {
            RegistrerViewModel registroVM = new RegistrerViewModel();
            return View(registroVM);
        }


        [HttpPost]
        public async Task<IActionResult> Registro(RegistrerViewModel rgViewModel)
        {
            // Validamos el modelo osea los datos que ponga en el registro
            if (ModelState.IsValid)
            {
                var usuario = new AppUsuario { UserName = rgViewModel.Email, Email = rgViewModel.Email, Nombre = rgViewModel.Nombre, Url = rgViewModel.Url, CodigoPais = rgViewModel.CodigoPais, Telefono = rgViewModel.Telefono, Pais = rgViewModel.Pais, Ciudad = rgViewModel.Ciudad, Direccion = rgViewModel.Direccion, FechaNacimiento = rgViewModel.FechaNacimiento, Estado = rgViewModel.Estado };
                var resultado = await _userManager.CreateAsync(usuario, rgViewModel.Password); // con esto dos ya crea el usuario

                if(resultado.Succeeded)
                {
                    // La persona quede autenticada dentro de la aplicacion
                    await _signInManager.SignInAsync(usuario, isPersistent: false);
                    return RedirectToAction("Index", "Home");
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
        public IActionResult Acceso()
        {

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Acceso(LoginViewModel accViewModel)
        {
            // Validamos el modelo osea los datos que ponga en el registro
            if (ModelState.IsValid)
            {
                var resultado = await _signInManager.PasswordSignInAsync(accViewModel.Email, accViewModel.Password, accViewModel.RememberMe, lockoutOnFailure: false); 

                if (resultado.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError(String.Empty, "Acceso inválido");
                    return View(accViewModel);
                }
            }
            return View(accViewModel);
        }
    }
}
