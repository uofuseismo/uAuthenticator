#ifndef UAUTHENTICATOR_SERVICE_PERMISSIONS_HPP
#define UAUTHENTICATOR_SERVICE_PERMISSIONS_HPP
#include <string>
namespace UAuthenticator
{
/// @brief Defines the access level for the callback.
/// @copyright Ben Baker distributed under the MIT license.
enum class Permissions
{
    None,      /*!< The user is not allowed to perform any task. */
    ReadOnly,  /*!< The user has read-only permissions and can perform
                    only GET operations. */
    ReadWrite, /*!< The user has permission to perform GET as well as
                    PUT, POST, and DELETE. */ 
};
/// @result The permissions in a string form.
[[nodiscard]] std::string permissionsToString(const Permissions permissions);
}
#endif
