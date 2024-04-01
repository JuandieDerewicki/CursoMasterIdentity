using CursoIdentityUdemy.Datos;
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
    }
}
