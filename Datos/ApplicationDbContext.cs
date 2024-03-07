using CursoIdentityUdemy.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CursoIdentityUdemy.Datos
{
    public class ApplicationDbContext : IdentityDbContext
    {

        public ApplicationDbContext(DbContextOptions options) : base(options) { }

        // Agregar los diferentes modelos 
        // Es importante pq si no ponemos esto no se agrega en la migracion
        public DbSet<AppUsuario> AppUsuario {  get; set; }  
    }
}
