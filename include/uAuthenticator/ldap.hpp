#ifndef UAUTHENTICATOR_BACKEND_LDAP_HPP
#define UAUTHENTICATOR_BACKEND_LDAP_HPP
#include <uAuthenticator/authenticator.hpp>
#include <memory>
namespace UAuthenticator
{
/// @class LDAP "ldap.hpp" "uAuthenticator/ldap.hpp"
/// @brief Defines a Lightweight Directory Access Protocol (LDAP)
///        authenticator for UUSS.
/// @copyright Ben Baker (University of Utah) distributed under the MIT license.
class LDAP : public IAuthenticator
{
public:
    /// @brief Defines the LDAP version protocol.
    enum class Version
    {   
        One = 1,
        Two = 2,
        Three = 3
    };
    /// @brief The directive specifies what checks to perform on client 
    ///        certificates in an incoming TLS session.
    enum class TLSVerifyClient
    {
        Never, /*!< Never ask for the client certificate.  This is the default. */
        Allow, /*!< The server will ask for a client certificate.  If none is
                    provided then the session proceeds normally.  If a certificate
                    is provided but the server cannot verify it, the certficate is
                    ignored and the session proceeds normally as if no
                    certificate had been provided. */
        Try,   /*!< The certificate is requested and if none is provided the
                    session proceeds normally.  If a certificate is provided
                    and it cannot be verfied then the session is immediately
                    terminated. */
        Demand /*!< The certificate must be provided and validated otherwise
                    the session is immediately terminated. */
    }; 
public:
    /// @brief Constructs an LDAP authenticator with the given server
    ///        address and port.
    /// @param[in] serverAddress         The server address - e.g., ldap://server.domain.com
    /// @param[in] port                  The port number.  This is typically 389 for
    ///                                  unencrypted connections and 636 for encrypted
    ///                                  (ldaps::/) connections.
    /// @param[in] organizationUnitName  The organization unit - e.g., ou=Groups
    /// @param[in] domainComponent       The domain component e.g., dc=gl,dc=google,dc=com
    /// @param[in] version               The LDAP version protocol.
    /// @param[in] issuer                The issuer that authorizes a user.
    ///                                  For example, this can be the utility and host.
    LDAP(const std::string &serverAddress,
         int port,
         const std::string &organizationalUnitName,
         const std::string &domainComponent,
         const Version version = Version::Three,
         const std::string &issuer = "ldap");
    /// @brief Constructs an LDAP authenticator with the given server
    ///        address and port.
    /// @param[in] serverAddress         The server address - e.g., ldaps://server.domain.com
    /// @param[in] port                  The port number.
    /// @param[in] organizationUnitName  The organization unit - e.g., ou=Groups
    /// @param[in] domainComponent       The domain component e.g., dc=gl,dc=google,dc=com
    /// @param[in] version               The LDAP version protocol.
    /// @param[in] tlsVerifyClient       For TLS this defines how we'll handle 
    ///                                  certificate validation.  This will
    ///                                  result in an environment variable being
    ///                                  adjusted.
    /// @param[in] issuer                The issuer that authorizes a user.
    ///                                  For example, this can be the utility and host.
    LDAP(const std::string &serverAddress,
         int port,
         const std::string &organizationalUnitName,
         const std::string &domainComponent,
         const Version version,
         const TLSVerifyClient tlsVerifyClient,
         const std::string &issuer = "ldap");
    /// @result True indicates the LDAP authenticator is initialized.
    [[nodiscard]] bool isInitialized() const noexcept;
    /// @result Returns true if the user with the password was authenticated.
    ///         Additionally, this will add the user, password to the list
    ///         of authenticated users upon which a JSON Web Token can be
    ///         obtained.
    [[nodiscard]] IAuthenticator::ReturnCode authenticate(const std::string &user,
                                                          const std::string &password,
                                                          const Permissions permissions) override final;
    /// @brief Disconnects.
    void unbind();
    /// @brief Destructor.
    ~LDAP() override;

    LDAP(const LDAP &) = delete;
    LDAP(LDAP &&) noexcept = delete;
    LDAP& operator=(const LDAP &) = delete;
    LDAP& operator=(LDAP &&) noexcept = delete;
private:
    class LDAPImpl;
    std::unique_ptr<LDAPImpl> pImpl;
};
}
#endif
