#ifndef UAUTHENTICATOR_SERVICE_AUTHENTICATOR_HPP
#define UAUTHENTICATOR_SERVICE_AUTHENTICATOR_HPP
#include <string>
#include <optional>
#include <memory>
#include <uAuthenticator/permissions.hpp>
namespace UAuthenticator
{
 class Credentials;
}
namespace UAuthenticator
{
/// @class IAuthenticator "authenticator.hpp" "uAuthenticator/authenticator.hpp"
/// @brief Defines a base class for an authenticator.
/// @copyright Ben Baker (University of Utah) distributed under the MIT license.
class IAuthenticator
{
public:
    enum class ReturnCode
    {
       Allowed,
       Denied,
       InternalError, 
    };
public:
    /// @brief Constructor.
    IAuthenticator();
    /// @brief Constructor with an issuer.  For example, the issuer could be
    ///        the host name + application name.
    explicit IAuthenticator(const std::string &issuer);
    /// @brief Destructor.
    virtual ~IAuthenticator();
    /// @brief Adds the user with given permissions.
    void add(const std::string &user,
             const Permissions permissions = Permissions::ReadOnly);
    /// @brief Removes the user.
    void remove(const std::string &user);
    /// @brief Authorizes the user based on their token.
    /// @result If the user was authorized then this returns the credentials
    ///         of the user with the specified JWT.  If this is null then
    ///         the user could not be authorized.
    [[nodiscard]] std::optional<Credentials> authorize(const std::string &jsonWebToken) const;
    /// @brief Gets the credentials of the user.
    [[nodiscard]] std::optional<Credentials> getCredentials(const std::string &user) const;
    /// @brief Upon successful authentication this will add the user and
    ///        password pair to the list of authenticated users.
    ///        Additionally, a JSON Web Token for the user will be obtainable
    ///        from \c getCredentials().
    /// @result True indicates the user with provided password was authenticated.
    [[nodiscard]] virtual IAuthenticator::ReturnCode authenticate(const std::string &user,
                                                  const std::string &password,
                                                  Permissions permissions) = 0;
private:
    class IAuthenticatorImpl;
    std::unique_ptr<IAuthenticatorImpl> pImpl;
};
}
#endif
