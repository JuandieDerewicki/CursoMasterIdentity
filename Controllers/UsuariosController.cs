using CursoIdentityUdemy.Datos;
using CursoIdentityUdemy.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CursoIdentityUdemy.Controllers
{
    public class UsuariosController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _contexto;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        public UsuariosController(UserManager<IdentityUser> userManager, ApplicationDbContext contexto)
        {
            _userManager = userManager; 
            _contexto = contexto;   
        }
        public IActionResult Index()
        {
            return View();
        }

        // Editar perfil
        public IActionResult EditarPerfil(string id)
        {
            if(id == null)
            {
                return NotFound();
            }
            var usuarioBd = _contexto.AppUsuario.Find(id);

            if(usuarioBd == null)
            {
                return NotFound();  
            }
            return View(usuarioBd); 
        }

        [HttpPost]
        public async Task<IActionResult> EditarPerfil(AppUsuario appusuario)
        {
            if(ModelState.IsValid)
            {
                var usuario = await _contexto.AppUsuario.FindAsync(appusuario.Id);
                usuario.Nombre = appusuario.Nombre;
                usuario.Url = appusuario.Url;
                usuario.CodigoPais = appusuario.CodigoPais;
                usuario.Telefono = appusuario.Telefono;
                usuario.Ciudad = appusuario.Ciudad;
                usuario.Pais = appusuario.Pais;
                usuario.Direccion = appusuario.Direccion;
                usuario.FechaNacimiento = appusuario.FechaNacimiento;

                await _userManager.UpdateAsync(usuario);

                return RedirectToAction(nameof(Index), "Home");   
            }
            return View();
        }

        // Cambiar contraseña cuando el usuario está autenticado
        public IActionResult CambiarPassword(string id)
        {
            return View();
        }
    }
}
