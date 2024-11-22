#ifndef UAUTHENTICATOR_CREDENTIALS_HPP
#define UAUTHENTICATOR_CREDENTIALS_HPP
#include <memory>
#include <optional>
#include <chrono>
#include <string>
#include <uAuthenticator/permissions.hpp>
namespace UAuthenticator
{
/// @class Credentials "credentials.hpp" "uAuthenticator/credentials.hpp"
/// @brief Defines a set of credentials that are commonly used for web
///        applications.
/// @copyright Ben Baker (University of Utah) distributed under the MIT license.
class Credentials
{
public:
    /// @name Constructors
    /// @{

    /// @brief Constructor.
    Credentials();
    /// @brief Copy constructor.
    /// @param[in] credentials  The credentials from which to initialize
    ///                         this class.
    Credentials(const Credentials &credentials);
    /// @brief Move constructor.
    /// @param[in,out] credentials  The credentials from which to initialize
    ///                             this class.  On exit, credentials's behavior
    ///                             is undefined.
    Credentials(Credentials &&credentials) noexcept;
    /// @}

    /// @brief Sets the user name.
    /// @param[in] user  The user name.
    void setUser(const std::string &user);
    /// @result The user name.
    [[nodiscard]] std::optional<std::string> getUser() const noexcept;

    /// @brief Sets the user's password.
    void setPassword(const std::string &password);
    /// @result The user's password.
    [[nodiscard]] std::optional<std::string> getPassword() const noexcept;

    /// @brief Sets the user's JSON web token.
    /// @param[in] token  The JWT.
    void setToken(const std::string &token);
    /// @result The web token.
    [[nodiscard]] std::optional<std::string> getToken() const;


    /// @brief Sets the user's permissions level.
    /// @param[in] permissions   The permissions level.
    void setPermissions(Permissions permissions) noexcept;
    /// @result The user's permissions which is by default read-only.
    [[nodiscard]] Permissions getPermissions() const noexcept;

    /// @brief Sets the time period the credentials are valid.
    void setIssuedAt(const std::chrono::seconds &issuedAt,
                     const std::chrono::seconds &duration = std::chrono::seconds {86400});
    /// @result The time when the credentials were issued.  By default
    ///         this is when the class was created. 
    [[nodiscard]] std::chrono::seconds getIssuedTime() const noexcept;
    /// @result The time when the credentials expire.  By default this
    ///         is one day from now.
    [[nodiscard]] std::chrono::seconds getExpirationTime() const noexcept;

    /// @name Destructors
    /// @{

    /// @brief Releases memory and resets the class.
    void clear() noexcept;
    /// @result Destructor.
    ~Credentials();
    /// @}

    /// @name Operators
    /// @{

    /// @brief Copy assignment.
    /// @param[in] credentials  The credentials to copy to this.
    /// @result A deep copy of the credentials.
    Credentials& operator=(const Credentials &credentials);
    /// @brief Move assignment.
    /// @param[in,out] credentials  The credentials whose memory will be moved
    ///                             to this.  On exit, credentials's behavior
    ///                             is undefined.
    /// @result The memory from credentials moved to this.
    Credentials& operator=(Credentials &&credentials) noexcept;
    /// @}
private:
    class CredentialsImpl;
    std::unique_ptr<CredentialsImpl> pImpl;
};
}
#endif
