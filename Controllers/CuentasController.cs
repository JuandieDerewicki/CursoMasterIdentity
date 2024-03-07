using CursoIdentityUdemy.Models;
using Microsoft.AspNetCore.Mvc;

namespace CursoIdentityUdemy.Controllers
{
    public class CuentasController : Controller
    {
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
    }
}
