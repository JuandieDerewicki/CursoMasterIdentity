using CursoIdentityUdemy.Datos;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace CursoIdentityUdemy.Controllers
{
    public class RolesController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _contexto;
        public RolesController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, ApplicationDbContext contexto)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _contexto = contexto;
        }

        [HttpGet]
        public IActionResult Index()
        {
            var roles = _contexto.Roles.ToList();
            return View();
        }

        [HttpGet]
        public IActionResult Crear()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Crear(IdentityRole rol)
        {
            if(await _roleManager.RoleExistsAsync(rol.Name))
            {
                return RedirectToAction(nameof(Index));
            }
            // Se crea el rol
            await _roleManager.CreateAsync(new IdentityRole() { Name = rol.Name });

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public IActionResult Editar(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                // Actualizar rol
                var rolBD = _contexto.Roles.FirstOrDefault(r => r.Id == id);
                return View(rolBD);
            }
        }
    }
}
