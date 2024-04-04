namespace CursoIdentityUdemy.Models
{
    public class ClaimsUsuarioViewModel
    {
        public ClaimsUsuarioViewModel()
        {
            Claims = new List<ClaimUsuario>();
        }
        public string IdUsuario { get; set; }
        public List<ClaimUsuario> Claims { get; set; } // para saber que permisos tiene cada usuario
        public class ClaimUsuario  // Creamos otra clase dentro de esta clase donde vamos a manejar el claim del usuario en forma individual
        {
            public string TipoClaim { get; set; }
            public bool Seleccionado { get; set; }
        }

    }
}
