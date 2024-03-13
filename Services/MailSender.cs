using MailKit.Security;
using Microsoft.AspNetCore.Identity.UI.Services;
using MimeKit.Text;
using MimeKit;
using MailKit.Net.Smtp;

namespace CursoIdentityUdemy.Services
{
    public class MailSender : IEmailSender
    {
        private readonly IConfiguration _config;

        public MailSender(IConfiguration config)
        {
            _config = config;
        }
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var correo_enviar = new MimeMessage();
            correo_enviar.From.Add(MailboxAddress.Parse(_config.GetSection("mail:Correo").Value));
            correo_enviar.To.Add(MailboxAddress.Parse(email));
            correo_enviar.Subject = subject;
            correo_enviar.Body = new TextPart(TextFormat.Html) { Text = htmlMessage };

            using var smtp = new SmtpClient();
            smtp.Connect("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
            smtp.Authenticate(_config.GetSection("mail:Correo").Value, _config.GetSection("mail:key").Value);
            smtp.Send(correo_enviar);
            smtp.Disconnect(true);
        }
    }
}
