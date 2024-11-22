#include <string>
#include <stdexcept>
#include "uAuthenticator/permissions.hpp"

using namespace UAuthenticator;

std::string UAuthenticator::permissionsToString(
    const Permissions permissions)
{
    if (permissions == Permissions::None)
    {
        return "none";
    }
    else if (permissions == Permissions::ReadOnly)
    {
        return "read-only";
    }
    else if (permissions == Permissions::ReadWrite)
    {
        return "read-write";
    }
    else
    {
        throw std::runtime_error("Unhandled permissions");
    }
}

