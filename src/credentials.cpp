#include <string>
#include <chrono>
#include "uAuthenticator/credentials.hpp"

using namespace UAuthenticator;

int64_t getNow()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>
              (now.time_since_epoch()).count();
}


class Credentials::CredentialsImpl
{
public:
    std::string mUser;
    std::string mPassword;
    std::chrono::seconds mIssuedAt{::getNow()};
    std::chrono::seconds mExpiresAt{mIssuedAt
                                  + std::chrono::seconds {86400}};
    Permissions mPermissions{Permissions::ReadOnly};
    bool mHavePassword{false};
};

/// Constructor
Credentials::Credentials() :
    pImpl(std::make_unique<CredentialsImpl> ())
{
}

/// Copy assignment
Credentials::Credentials(const Credentials &credentials)
{
    *this = credentials;
}

/// Move assignment
Credentials::Credentials(Credentials &&credentials) noexcept
{
    *this = std::move(credentials);
}

/// Reset class
void Credentials::clear() noexcept
{
    pImpl = std::make_unique<CredentialsImpl> ();
}

/// Destructor
Credentials::~Credentials() = default;

/// Copy assignment
Credentials& Credentials::operator=(const Credentials &credentials)
{
    if (&credentials == this){return *this;}
    pImpl = std::make_unique<CredentialsImpl> (*credentials.pImpl);
    return *this;
}

/// Move assignment
Credentials& Credentials::operator=(Credentials &&credentials) noexcept
{
    if (&credentials == this){return *this;}
    pImpl = std::move(credentials.pImpl);
    return *this;
}

/// User name
void Credentials::setUser(const std::string &user)
{
    if (user.empty()){throw std::invalid_argument("User is empty");}
    pImpl->mUser = user;
}

std::optional<std::string> Credentials::getUser() const noexcept
{
    return !pImpl->mUser.empty() ?
           std::optional<std::string> (pImpl->mUser) : std::nullopt;
}

/// Password
void Credentials::setPassword(const std::string &password)
{
    pImpl->mPassword = password;
    pImpl->mHavePassword = true;
}

std::optional<std::string> Credentials::getPassword() const noexcept
{
    return pImpl->mHavePassword ?
           std::optional<std::string> (pImpl->mPassword) : std::nullopt;
}

/// Permissions
void Credentials::setPermissions(const Permissions permissions) noexcept
{
    pImpl->mPermissions = permissions;
}

Permissions Credentials::getPermissions() const noexcept
{
    return pImpl->mPermissions;
}

/// Valid periods
void Credentials::setIssuedAt(
    const std::chrono::seconds &issuedAt,
    const std::chrono::seconds &duration)
{
    if (duration.count() < 0)
    {
        throw std::invalid_argument("Duration must be non-negative");
    }
    pImpl->mIssuedAt = issuedAt;
    pImpl->mExpiresAt = pImpl->mIssuedAt + duration;
}

std::chrono::seconds Credentials::getIssuedTime() const noexcept
{
    return pImpl->mIssuedAt;
}

std::chrono::seconds Credentials::getExpirationTime() const noexcept
{
    return pImpl->mExpiresAt;
}
