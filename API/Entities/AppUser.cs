using System.ComponentModel.DataAnnotations;

namespace API.Entities
{
    public class AppUser
    {

        public int Id { get; set; }
        [Required]
        public string Name { get; set; }
        public byte[] PasswordHasch { get; set; }
        public byte[] PasswordSalt { get; set; }

    }
}
