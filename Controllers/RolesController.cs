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
            return View();
        }
    }
}
