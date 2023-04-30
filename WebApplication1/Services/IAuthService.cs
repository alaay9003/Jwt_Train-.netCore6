using Jwt_Train.Models;

namespace Jwt_Train.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterModel(RegisterModel model);
        Task<AuthModel> GetTokenAsync(SignInModel model);

        Task<String> AddRoleAsync(AddRoleModel model);
    }
}
