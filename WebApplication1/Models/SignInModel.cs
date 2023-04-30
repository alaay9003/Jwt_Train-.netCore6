using System.ComponentModel.DataAnnotations;

namespace Jwt_Train.Models
{
    public class SignInModel
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public String Password { get; set; }
    }
}
