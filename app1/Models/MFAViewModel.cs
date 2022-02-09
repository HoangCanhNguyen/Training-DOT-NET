using System.ComponentModel.DataAnnotations;

namespace app1.Models
{
    public class MFAViewModel
    {
        [Required]
        public string Token { get; set; }
        public string Code { get; set; }

        public string QrcodeUrl { get; set; }
    }
}
