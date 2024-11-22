#include <string>
#include <map>
#include <chrono>
#include <mutex>
#include <optional>
#include <jwt-cpp/jwt.h>
#include <boost/asio/ip/host_name.hpp>
#include "uAuthenticator/authenticator.hpp"
#include "uAuthenticator/credentials.hpp"
#include "uAuthenticator/permissions.hpp"

#define JWT_TYPE "JWT"

using namespace UAuthenticator;

namespace
{
/*
struct LocalCredentials
{
    std::string jsonWebToken;
    std::string user;
    int64_t issuedAt;
    int64_t expiresAt;
    Permissions permissions{Permissions::None};
};
*/

int64_t getNow()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>
              (now.time_since_epoch()).count();
}

}

class IAuthenticator::IAuthenticatorImpl
{
public:
    explicit IAuthenticatorImpl(const std::string &issuer) :
        mIssuer(issuer)
    {
    }
/*
    [[nodiscard]] ::LocalCredentials createCredentials2(const std::string &user)
    {
        auto now = std::chrono::system_clock::now();
        auto expirationTime
            = jwt::date(now + mExpirationDuration); 
        std::string token = jwt::create()
                                .set_type(JWT_TYPE)
                                .set_issued_at(now)
                                .set_expires_at(expirationTime)
                                .set_issuer(mIssuer)
                                .set_audience(user)
                                .sign(jwt::algorithm::hs256{mKey});
        auto nowInSeconds
            = std::chrono::duration_cast<std::chrono::seconds>
              (now.time_since_epoch()).count();
        ::LocalCredentials result;  
        result.jsonWebToken = std::move(token);
        result.user = user;
        result.issuedAt = nowInSeconds;
        result.expiresAt = nowInSeconds + mExpirationDuration.count();
        result.permissions = Permissions::ReadWrite;
        //std::cout << result.issuedAt << " " << result.expiresAt << std::endl;
        //std::cout << result.jsonWebToken << std::endl;
        return result;
    }
*/
    [[nodiscard]]
    Credentials createCredentials(const std::string &user,
                                  const Permissions permissions)
    {
        auto now = std::chrono::system_clock::now();
        auto expirationTime
            = jwt::date(now + mExpirationDuration); 
        std::string token = jwt::create()
                                .set_type(JWT_TYPE)
                                .set_issued_at(now)
                                .set_expires_at(expirationTime)
                                .set_issuer(mIssuer)
                                .set_audience(user)
                                .sign(jwt::algorithm::hs256{mKey});
        auto nowInSeconds
            = std::chrono::duration_cast<std::chrono::seconds>
              (now.time_since_epoch()).count();
        Credentials result;
        result.setUser(user);
        result.setPermissions(permissions);
        result.setToken(token);
        result.setIssuedAt(std::chrono::seconds {nowInSeconds},
                           mExpirationDuration);
        return result;
    }
    [[nodiscard]] bool verified(const std::string &token) const
    {
        auto verifier = jwt::verify()
            .with_issuer(mIssuer)
            .with_type(JWT_TYPE)
            .allow_algorithm(jwt::algorithm::hs256{mKey});
        auto decodedToken = jwt::decode(token);
        try
        {
            verifier.verify(decodedToken);
            return true;
        }
        catch (const std::exception &e)
        {
            //spdlog::info(e.what());
            return false;
        }
    }
    void add(const std::string &userName, const Credentials &credentials)
    {
        auto user = credentials.getUser();
        if (!user){throw std::invalid_argument("User not set");}
        if (*user != userName)
        {
            throw std::runtime_error("Inconstinent user names");
        }
        //auto jwt = credentials.getToken();
        //if (!jwt){throw std::invalid_argument("JSON web token not set");}
        // Add or overwrite it
        std::lock_guard<std::mutex> lockGuard(mMutex);
        auto userIndex = mUserKeysMap.find(userName);
        if (userIndex == mUserKeysMap.end())
        {
            mUserKeysMap.insert(std::pair {userName, credentials});
        }
        else
        {
            userIndex->second = credentials;
        }   
    }
    void add(const std::string &user, const Permissions permissions)
    {
        add(user, createCredentials(user, permissions));
    }
    std::optional<Credentials> find(const std::string &user) const
    {
        Credentials credentials;
        {
        std::lock_guard<std::mutex> lockGuard(mMutex);
        auto idx = mUserKeysMap.find(user);
        if (idx != mUserKeysMap.end())
        {
            return std::optional<Credentials> {idx->second};
        }
        }
        return std::nullopt; 
    }
    [[nodiscard]] std::optional<Credentials>
        getCredentials(const std::string &user) const noexcept
    {
        Credentials result;
        {
        std::lock_guard<std::mutex> lockGuard(mMutex);
        auto idx = mUserKeysMap.find(user);
        if (idx != mUserKeysMap.end())
        {
            return std::optional<Credentials> {idx->second};
        }
        }
        return std::nullopt;
    }
    mutable std::mutex mMutex;
    std::map<std::string, Credentials> mUserKeysMap;
    std::string mIssuer{boost::asio::ip::host_name()};
    std::string mKey{boost::asio::ip::host_name()
                     + ":"
                     + std::to_string(getNow())
                    };
    std::chrono::seconds mExpirationDuration{86400};
};

/// Constructor
IAuthenticator::IAuthenticator() :
    pImpl(std::make_unique<IAuthenticatorImpl>
          (boost::asio::ip::host_name()))
{
}

IAuthenticator::IAuthenticator(const std::string &issuer) :
    pImpl(std::make_unique<IAuthenticatorImpl> (issuer))
{
}

void IAuthenticator::add(const std::string &user,
                         const Permissions permissions)
{
    if (user.empty()){throw std::invalid_argument("User is empty");}
    pImpl->add(user, permissions); 
}

void IAuthenticator::remove(const std::string &user)
{
    if (pImpl->mUserKeysMap.contains(user))
    {
        pImpl->mUserKeysMap.erase(user);
    } 
}

std::optional<Credentials> IAuthenticator::authorize(
    const std::string &jsonWebToken) const
{
    // First thing - we verify the token is legit and lift the user
    std::string user;
    try
    {
        auto decodedToken = jwt::decode(jsonWebToken);
        if (!decodedToken.has_audience())
        {
            throw std::invalid_argument("User not found in token");
        }
        if (!decodedToken.has_expires_at())
        {
            throw std::invalid_argument("Key expiration not set");
        }
        auto verifier = jwt::verify()
                           .with_type(JWT_TYPE)
                           .with_issuer(pImpl->mIssuer)
                           .allow_algorithm(jwt::algorithm::hs256{pImpl->mKey})
                           .leeway(1U);
        verifier.verify(decodedToken);
        auto audience = decodedToken.get_audience();
        if (audience.size() != 1)
        {
            //spdlog::critical("Audience has wrong size");
            throw std::runtime_error("Audience has wrong size");
        }
        user = *audience.begin(); //std::string (*audience.begin());
    }
    catch (const jwt::error::token_verification_exception &e)
    {
        //spdlog::debug("Token cannot be verified because "
        //            + std::string {e.what()});
        throw std::invalid_argument("Token cannot be verified because "
                                  + std::string {e.what()});
    }
    catch (const std::exception &e) 
    {
        //spdlog::debug("Token malformed because " + std::string {e.what()});
        throw std::invalid_argument("Malformed token");
    }
    if (user.empty()){throw std::invalid_argument("User name is empty");}
 
    // Okay the token is legit and we have a user -> are they good to go?
    return pImpl->find(user);
}

/// Get credentials for user
std::optional<Credentials>
IAuthenticator::getCredentials(const std::string &user) const
{
    return pImpl->getCredentials(user);
}

/// Destructor
IAuthenticator::~IAuthenticator() = default;
