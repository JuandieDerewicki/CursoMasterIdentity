using Microsoft.AspNetCore.Identity;

namespace CursoIdentityUdemy.Models
{
    public class AppUsuario : IdentityUser
    {
        public string Nombre { get; set; }
        public string Url { get; set; }
        public Int32 CodigoPais { get; set; }
        public string Telefono { get; set; }
        public string Pais { get; set; }
        public string Ciudad { get; set; }
        public string Direccion { get; set; }
        public DateTime FechaNacimiento { get; set; }
        public bool Estado { get; set; }

        // De esta manera estamos ampliando o profundizando, ya que, los que vienen por defecto son los funcionales para hacer registro o login pero de esta manera extendiendo IdentityUser creamos la clase dentro de Model con los datos que quiero 
    }
}
