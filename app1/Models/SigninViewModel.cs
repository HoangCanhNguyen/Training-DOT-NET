using System.ComponentModel.DataAnnotations;

namespace app1.Models
{
    public class SigninViewModel
    {
        [Required]
        [DataType(DataType.EmailAddress, ErrorMessage = "Email address is missing or invalid")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Email address is missing")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}
