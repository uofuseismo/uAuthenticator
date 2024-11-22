#include <iostream>
#include <cstdint>
#include <limits>
#include "uAuthenticator/ldap.hpp"
extern "C"
{
#include <ldap.h>
}

// https://www.middleware.vt.edu/ed/ldap/edauth-examples.html#cc-applications


class UAuthenticator::LDAP::LDAPImpl
{
public:
    LDAPImpl(const std::string &serverAddress,
             const int port,
             const std::string &organizationalUnitName,
             const std::string &domainComponent,
             const UAuthenticator::LDAP::Version ldapVersion)
    {
        if (serverAddress.empty())
        {
            throw std::invalid_argument("Server address is empty");
        }
        if (port < 0 || port > std::numeric_limits<uint16_t>::max())
        {
            std::invalid_argument("Port out of range");
        }
        mServerAddress = serverAddress + ":" + std::to_string(port);
        mDNSuffix = organizationalUnitName + "," + domainComponent;
        mVersion = ldapVersion;
    }
    ~LDAPImpl()
    {
        unbind();
    }
    void unbind()
    {
        if (mBound)
        {
            //spdlog::debug("LDAPImpl::unbind: Unbinding LDAP connection");
            auto returnCode
                = ldap_unbind_ext(mLDAP, &mServerControl, &mClientControl);
            if (returnCode != LDAP_SUCCESS)
            {
                std::string error{ldap_err2string(returnCode)};
                //spdlog::critical("LDAPImpl::unbind failed with: " + error);
                throw std::runtime_error("Failed to unbind because " + error);
            }
            mBound = false;
        }
    }
    /// @brief initializing the connection.
    void initialize()
    {
        unbind();
        //spdlog::debug("LDAPImpl::initialize: Initializing connection to "
        //            + mServerAddress);
        if (ldap_initialize(&mLDAP, mServerAddress.c_str()) != LDAP_SUCCESS)
        {
            mBound = true;
            //spdlog::critical(
            //    "LDAPImpl::initialize: Failed to bind to LDAP server at: "
            //  + mServerAddress);
            throw std::runtime_error("Failed to bind to LDAP server at: "
                                   + mServerAddress);
            return;
        }
        // Set the version
        auto version{LDAP_VERSION3};
        if (mVersion == Version::One)
        {
            version  = LDAP_VERSION1;
        }
        else if (mVersion == Version::Two)
        {
            version = LDAP_VERSION2;
        }
        else
        {
            version = LDAP_VERSION3;
        }
        auto returnCode = ldap_set_option(mLDAP,
                                          LDAP_OPT_PROTOCOL_VERSION,
                                          &version);
        if (returnCode != LDAP_SUCCESS)
        {
            //spdlog::critical("LDAPImpl::Failed to set version");
            unbind();
            //return;
            throw std::runtime_error("Failed to set LDAP version");
        }
    }

    ::LDAP *mLDAP{nullptr};
    LDAPControl *mClientControl{nullptr};
    LDAPControl *mServerControl{nullptr};
    std::string mServerAddress;
    std::string mDNSuffix;
    Version mVersion{Version::Three};
    bool mBound{false};
};

/// Construtor
UAuthenticator::LDAP::LDAP(const std::string &serverAddress,
                           const int port,
                           const std::string &organizationalUnitName,
                           const std::string &domainComponent,
                           const UAuthenticator::LDAP::Version ldapVersion,
                           const std::string &issuer) :
    pImpl(std::make_unique<LDAPImpl> (serverAddress,
                                      port,
                                      organizationalUnitName,
                                      domainComponent,
                                      ldapVersion)),
    IAuthenticator(issuer)
{
    pImpl->initialize();
}
 
/// Constructor
UAuthenticator::LDAP::LDAP(const std::string &serverAddress,
                       const int port,
                       const std::string &organizationalUnitName,
                       const std::string &domainComponent,
                       const UAuthenticator::LDAP::Version ldapVersion,
                       const UAuthenticator::LDAP::TLSVerifyClient verify,
                       const std::string &issuer) :
    pImpl(std::make_unique<LDAPImpl> (serverAddress,
                                      port,
                                      organizationalUnitName,
                                      domainComponent,
                                      ldapVersion)),
    IAuthenticator(issuer)
{ 
    constexpr int overwrite{1};
    if (verify == UAuthenticator::LDAP::TLSVerifyClient::Never)
    {
        if (setenv("LDAPTLS_REQCERT", "NEVER", overwrite) != 0)
        {
            throw std::runtime_error(
               "LDAP: Failed to update LDAPTLS_REQCERT to NEVER");
        }
    }
    else if (verify == UAuthenticator::LDAP::TLSVerifyClient::Allow)
    {
        if (setenv("LDAPTLS_REQCERT", "ALLOW", overwrite) != 0)
        {
            throw std::runtime_error(
               "LDAP: Failed to update LDAPTLS_REQCERT to ALLOW");
        } 
    }
    else if (verify == UAuthenticator::LDAP::TLSVerifyClient::Try)
    {
        if (setenv("LDAPTLS_REQCERT", "TRY", overwrite) != 0)
        {
            throw std::runtime_error(
               "LDAP: Failed to update LDAPTLS_REQCERT to TRY");
        }
    }
    else if (verify == UAuthenticator::LDAP::TLSVerifyClient::Demand)
    {
        if (setenv("LDAPTLS_REQCERT", "DEMAND", overwrite) != 0)
        {
            throw std::runtime_error(
               "LDAP: Failed to update LDAPTLS_REQCERT to DEMAND");
        }
    }
    pImpl->initialize();
}

/// @result True indicates the LDAP authenticator is initialized.
[[nodiscard]] bool UAuthenticator::LDAP::isInitialized() const noexcept
{
    return pImpl->mBound;
}

/// @result True indicates the user is permitted
UAuthenticator::IAuthenticator::ReturnCode 
UAuthenticator::LDAP::authenticate(
    const std::string &user,
    const std::string &password,
    const Permissions permissions)
{
    if (user.empty())
    {
        throw std::invalid_argument("User name must be specified");
    }
    auto temporaryPassword{password};
    struct berval *serverCredential{nullptr};
    auto dn = "uid=" + user + "," + pImpl->mDNSuffix;

    struct berval credential;
    credential.bv_val = temporaryPassword.data();
    credential.bv_len = temporaryPassword.size();
    auto returnCode
        = ldap_sasl_bind_s(pImpl->mLDAP, dn.c_str(),
                           LDAP_SASL_SIMPLE,
                           &credential, NULL, NULL, &serverCredential);
    if (returnCode != LDAP_SUCCESS)
    {
        if (returnCode != LDAP_INVALID_CREDENTIALS)
        {
            std::string error{ldap_err2string(returnCode)};
            throw std::runtime_error("Could not bind to SASL; failed with: "
                                   + error);
        }
        return IAuthenticator::ReturnCode::Denied;
        //spdlog::info("Rejected " + user);
    }
    // LDAP says the user is okay - now add the user
    try
    {
        this->add(user, permissions);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(
            "LDAP::authenticate: Failed to add user; failed with: "
          + std::string {e.what()});
        //return IAuthenticator::ReturnCode::ServerError;
    }
    return IAuthenticator::ReturnCode::Allowed;
}

/// Disconnect
void UAuthenticator::LDAP::unbind()
{
    pImpl->unbind();
}

/// Destructor
UAuthenticator::LDAP::~LDAP() = default;
 

