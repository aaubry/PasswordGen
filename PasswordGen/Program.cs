// Copyright 2010 Antoine Aubry
// 
// This file is part of PasswordGen.
// 
// PasswordGen is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// PasswordGen is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with PasswordGen. If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web.Security;

namespace PasswordGen {
	public class Program {
		public static void Main(string[] args) {
			const string defaultAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!*#%$&";

			Console.WriteLine("PasswordGen  Copyright (C) 2010 Antoine Aubry");
			Console.WriteLine("This program comes with ABSOLUTELY NO WARRANTY.");
			Console.WriteLine("This is free software, and you are welcome to redistribute it under certain conditions.");
			Console.WriteLine();

			if(args.Length == 0)
			{
				Console.WriteLine("Enter the password length:");
			}

			string length = args.Length > 0 ? args[0] : Console.ReadLine();

			int size;
			if (!int.TryParse(length, out size))
			{
				Console.WriteLine("Usage: PasswordGen [<size> [<alphabet>]]");
				Console.WriteLine();
				return;
			}

			string alphabet = args.Length == 2 ? args[1] : defaultAlphabet;

			RandomNumberGenerator rng = RandomNumberGenerator.Create();

			StringBuilder passwordBuilder = new StringBuilder();
			for (int i = 0; i < size; ++i)
			{
				int index = NextValue(rng, alphabet.Length);
				passwordBuilder.Append(alphabet[index]);
			}

			string password = passwordBuilder.ToString();
			byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
			byte[] sha1 = SHA1.Create().ComputeHash(passwordBytes);
			byte[] md5 = MD5.Create().ComputeHash(passwordBytes);

			Console.WriteLine("Password:         {0}", password);
			Console.WriteLine();
			Console.WriteLine("SHA1 base-64:     {0}", Convert.ToBase64String(sha1));
			Console.WriteLine("SHA1 hex:         {0}", ToHexString(sha1));
			Console.WriteLine("SHA1 WebForms:    {0}", FormsAuthentication.HashPasswordForStoringInConfigFile(password, "sha1"));
			Console.WriteLine();
			Console.WriteLine("MD5 base-64:      {0}", Convert.ToBase64String(md5));
			Console.WriteLine("MD5 hex:          {0}", ToHexString(md5));
			Console.WriteLine("MD5 WebForms:     {0}", FormsAuthentication.HashPasswordForStoringInConfigFile(password, "md5"));
			Console.WriteLine();

			Console.Write("Random bytes:     ");
		
			byte[] bytes = new byte[size];
			rng.GetBytes(bytes);
			foreach(var b in bytes)
			{
				Console.Write(b.ToString("X02"));
			}
			Console.WriteLine();

			Console.Write("Bytes in decimal: ");
			for (int i = 0; i < size; ++i)
			{
				if(i > 0)
				{
					Console.Write(", ");
				}
				Console.Write(bytes[i]);
			}
			Console.WriteLine();

			if (args.Length == 0)
			{
				Console.WriteLine("Press ESC to exit...");
				while (Console.ReadKey().Key != ConsoleKey.Escape)
				{
				}
			}
		}

		private static string ToHexString(IEnumerable<byte> bytes)
		{
			StringBuilder buffer = new StringBuilder();
			foreach (byte b in bytes)
			{
				buffer.Append(b.ToString("D2"));
			}
			return buffer.ToString();
		}

		private static int NextValue(RandomNumberGenerator rng, int maxValueExclusive) {
			byte[] bytes = new byte[1];
			do {
				rng.GetBytes(bytes);
			} while(bytes[0] >= maxValueExclusive);
			return bytes[0];
		}
	}
}
