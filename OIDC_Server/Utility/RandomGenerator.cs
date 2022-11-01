using Microsoft.AspNetCore.Mvc;
using System;

namespace OIDC_Server.Utility
{
    public static class RandomGenerator
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        public static string GenerateString(int length)
         => new(Enumerable.Repeat(chars, length)
                .Select(s => s[Random.Shared.Next(s.Length)]).ToArray());

    }
}
