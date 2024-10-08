﻿using System.ComponentModel.DataAnnotations;

namespace IdentityApp.ViewModels
{
    public class CreateViewModel
    {
        [Required]
        public string? FullName { get; set; }

        [Required]
        public string? UserName { get; set; }

        [Required]
        [EmailAddress]
        public string? Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string? Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Parola eşleşmiyor.")]
        public string? ConfirmPassword { get; set; }

    }
}
