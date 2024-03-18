using System.ComponentModel.DataAnnotations;

namespace CursoIdentityUdemy.Models
{
    public class ConfirmacionAccesoExternoViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Name { get; set; }

    }
}
