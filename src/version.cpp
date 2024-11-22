#include <string>
#include "uAuthenticator/version.hpp"

using namespace UAuthenticator;

int Version::getMajor() noexcept
{
    return uAuthenticator_MAJOR;
}

int Version::getMinor() noexcept
{
    return uAuthenticator_MINOR;
}

int Version::getPatch() noexcept
{
    return uAuthenticator_PATCH;
}

bool Version::isAtLeast(const int major, const int minor,
                        const int patch) noexcept
{
    if (uAuthenticator_MAJOR < major){return false;}
    if (uAuthenticator_MAJOR > major){return true;}
    if (uAuthenticator_MINOR < minor){return false;}
    if (uAuthenticator_MINOR > minor){return true;}
    if (uAuthenticator_PATCH < patch){return false;}
    return true;
}

std::string Version::getVersion() noexcept
{
    std::string version(uAuthenticator_VERSION);
    return version;
}
