/*
 * passwd.c : Functions handling passwd entries retrieval.
 */

#include "nss-rightscale.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

/**
 * Setup everything needed to retrieve passwd entries.
 */
enum nss_status _nss_rightscale_setpwent(void) {
    NSS_DEBUG("Initializing pw functions\n");
    return NSS_STATUS_SUCCESS;
}

/*
 * Free getpwent resources.
 */
enum nss_status _nss_rightscale_endpwent(void) {
    NSS_DEBUG("Finishing pw functions\n");
    return NSS_STATUS_SUCCESS;
}

/*
 * Return next passwd entry.
 * Not implemeted yet.
 */

enum nss_status _nss_rightscale_getpwent_r(struct passwd *pwbuf, char *buf,
            size_t buflen, int *errnop) {
    NSS_DEBUG("Getting next pw entry\n");
    return NSS_STATUS_UNAVAIL;
}

/**
 * Get user info by username.
 */

enum nss_status _nss_rightscale_getpwnam_r(const char* name, struct passwd *pwbuf,
            char *buf, size_t buflen, int *errnop)
{
    enum nss_status res;
    int fd;

    NSS_DEBUG("getpwnam_r: Looking for user %s\n", name);

    res = open_passwd(&fd, errnop);
    if(res != NSS_STATUS_SUCCESS) return res;
    res = read_getpwnam(fd, pwbuf, buf, buflen, errnop);
    close_passwd(fd);

    return res;
}

/*
 * Get user by UID.
 */

enum nss_status _nss_rightscale_getpwuid_r(uid_t uid, struct passwd *pwbuf,
               char *buf, size_t buflen, int *errnop) {
    int res;
    int fd;

    NSS_DEBUG("getpwuid_r: looking for user #%d\n", uid);

    res = open_passwd(&fd, errnop);
    if(res != NSS_STATUS_SUCCESS) return res;
    res = read_getpwuid(fd, pwbuf, buf, buflen, errnop);
    close_passwd(fd);

    return res;
}

