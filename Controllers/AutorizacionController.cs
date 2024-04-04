using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CursoIdentityUdemy.Controllers
{
    public class AutorizacionController : Controller
    {
        [AllowAnonymous]
        public IActionResult AccesoPublico()
        {
            return View();
        }

        [Authorize]
        public IActionResult AccesoAutenticado()
        {
            return View();
        }
        //[Authorize(Roles = "Usuario")]
        [Authorize(Policy = "Usuario")]
        public IActionResult AccesoUsuario()
        {
            return View();
        }

        //[Authorize(Roles = "Registrado")]
        [Authorize(Policy = "Registrado")]
        public IActionResult AccesoRegistrado()
        {
            return View();
        }

        // Opcion 1 con roles
        //[Authorize(Roles = "Administrador")]
        // Opcion 2 con policy o directivas
        [Authorize(Policy = "Administrador")]

        public IActionResult AccesoAdministrador()
        {
            return View();
        }

        [Authorize(Roles = "Usuario, Administrador")]
        public IActionResult AccesoUsuarioAdministrador()
        {
            return View();
        }

        [Authorize(Policy = "UsuarioYAdministrador")]
        public IActionResult AccesoUsuarioYAdministrador()
        {
            return View();
        }

        [Authorize(Policy = "AdministradorCrear")]
        public IActionResult AccesoAdministradorPermisoCrear()
        {
            return View();
        }

        [Authorize(Policy = "AdministradorEditarBorrar")]
        public IActionResult AccesoAdministradorPermisoEditarBorrar()
        {
            return View();
        }

        [Authorize(Policy = "AdministradorCrearEditarBorrar")]
        public IActionResult AccesoAdministradorPermisoCrearEditarBorrar()
        {
            return View();
        }
    }
}

