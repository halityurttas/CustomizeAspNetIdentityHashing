using Microsoft.AspNet.Identity;

/* PwdDecorator project on https://github.com/halityurttas/PasswordHashingWithDecoratorPattern */
using PwdWDecorator.Decorator;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Configuration;

namespace WebApplication.Libraries
{
    public class IdentityPasswordHasher : PasswordHasher, IPasswordHasher
    {
        public FormsAuthPasswordFormat FormsAuthPasswordFormat { get; set; }

        public IdentityPasswordHasher()
        {
            FormsAuthPasswordFormat = FormsAuthPasswordFormat.Clear;
        }

        public override string HashPassword(string password)
        {
            MD5Decorator md5 = new MD5Decorator();
            SHADecorator sha = new SHADecorator();
            md5.SetComponent(sha);
            return md5.Hash(password);
        }

        public override PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            return hashedPassword.Equals(HashPassword(providedPassword)) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}