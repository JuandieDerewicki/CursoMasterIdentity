using System.ComponentModel.DataAnnotations;

namespace CursoIdentityUdemy.Models
{
    public class CambiarPasswordViewModel
    {
        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")] // Para que aparezca en español con la Ñ
        public string Password { get; set; }

        [Required(ErrorMessage = "La confirmacion de contraseña es obligatoria")]
        [Compare("Password", ErrorMessage = "La contraseña y confirmación de contraseña no coinciden")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirmar Contraseña")] // Para que aparezca en español con la Ñ
        public string ConfirmPassword { get; set; }
    }
}
