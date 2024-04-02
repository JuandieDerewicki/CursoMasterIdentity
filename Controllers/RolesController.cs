using CursoIdentityUdemy.Datos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace CursoIdentityUdemy.Controllers
{
    [Authorize(Roles = "Administrador")]
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
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Crear(IdentityRole rol)
        {
            if(await _roleManager.RoleExistsAsync(rol.Name))
            {
                TempData["Error"] = "El rol ya existe"; // El TEMPDATA es para mostrar errores
                return RedirectToAction(nameof(Index));
            }
            // Se crea el rol
            await _roleManager.CreateAsync(new IdentityRole() { Name = rol.Name });
            TempData["Correcto"] = "Rol creado correctamente"; // El TEMPDATA es para mostrar errores
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Editar(IdentityRole rol)
        {
            if (await _roleManager.RoleExistsAsync(rol.Name))
            {
                TempData["Error"] = "El rol ya existe"; // El TEMPDATA es para mostrar errores
                return RedirectToAction(nameof(Index));
            }
            // Se crea el rol
            var rolBD = _contexto.Roles.FirstOrDefault(r => r.Id == rol.Id);
            if(rolBD == null)
            {
                return RedirectToAction(nameof(Index));
            }
            rolBD.Name = rol.Name;
            rolBD.NormalizedName = rol.Name.ToUpper();
            var resultado = await _roleManager.UpdateAsync(rolBD);
            TempData["Correcto"] = "Rol editado correctamente"; // El TEMPDATA es para mostrar errores
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Borrar(string id)
        {
            var rolBD = _contexto.Roles.FirstOrDefault(r => r.Id == id);
            if (rolBD == null)
            {
                TempData["Error"] = "No existe el rol"; // El TEMPDATA es para mostrar errores
                return RedirectToAction(nameof(Index));
            }

            var usuarioParaEsteRol = _contexto.UserRoles.Where(u => u.RoleId == id).Count();
            if(usuarioParaEsteRol > 0)
            {
                TempData["Error"] = "El rol tiene usuarios, no se puede borrar"; // El TEMPDATA es para mostrar errores
                return RedirectToAction(nameof(Index));
            }

            await _roleManager.DeleteAsync(rolBD);
            TempData["Correcto"] = "Rol borrado correctamente"; // El TEMPDATA es para mostrar errores
            return RedirectToAction(nameof(Index));
        }
    }
}
