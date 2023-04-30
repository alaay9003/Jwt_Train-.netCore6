using System.ComponentModel.DataAnnotations;

namespace Jwt_Train.Models
{
    public class AddRoleModel
    {
        [Required]
        public string UserId { get; set; }
        [Required]
        public string RoleName { get; set; }
    }
}
