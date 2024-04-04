using Microsoft.AspNetCore.Mvc;

namespace CursoIdentityUdemy.Controllers
{
    public class AutorizacionController : Controller
    {
        public IActionResult AccesoPublico()
        {
            return View();
        }

        public IActionResult AccesoAutenticado()
        {
            return View();
        }

        public IActionResult AccesoUsuario()
        {
            return View();
        }

        public IActionResult AccesoRegistrado()
        {
            return View();
        }

        public IActionResult AccesoAdministrador()
        {
            return View();
        }

        public IActionResult AccesoUsuarioAdministrador()
        {
            return View();
        }

        public IActionResult AccesoUsuarioYAdministrador()
        {
            return View();
        }

        public IActionResult AccesoAdministradorPermisoCrear()
        {
            return View();
        }

        public IActionResult AccesoAdministradorPermisoEditarBorrar()
        {
            return View();
        }

        public IActionResult AccesoAdministradorPermisoCrearEditarBorrar()
        {
            return View();
        }
    }
}

