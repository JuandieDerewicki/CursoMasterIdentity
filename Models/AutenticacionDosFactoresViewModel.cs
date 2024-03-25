using System.ComponentModel.DataAnnotations;

namespace CursoIdentityUdemy.Models
{
    public class AutenticacionDosFactoresViewModel
    {
        // Para el acceso (login)
        [Required]
        [Display(Name = "Código del autenticador")]
        public string Code { get; set; }   

        // Para el registro
        public string Token { get; set; }
    }
}
