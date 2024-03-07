using System.ComponentModel.DataAnnotations;

namespace CursoIdentityUdemy.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "El email es obligatorio")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")] // Para que aparezca en español con la Ñ
        public string Password { get; set; }

        [Display(Name = "Recordar datos")] // Para que aparezca en español 
        public bool RememberMe { get; set; } // Para recordar los datos de acceso
     
    }
}
