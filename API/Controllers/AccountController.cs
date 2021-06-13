using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{

    public class AccountController : BaseController
    {
        private readonly DataContext _context;        
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;            
            _context = context;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto reguser)
        {
            if (await UserExists(reguser.UserName)) return BadRequest("Username is available");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = reguser.UserName,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(reguser.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto logindetails)
        {
            var user = await _context.Users.SingleOrDefaultAsync(u => u.UserName == logindetails.userName);

            if (user == null) return Unauthorized("Invalid UserName");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(logindetails.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }

            return new UserDto
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(u => u.UserName == username);
        }

    }
}