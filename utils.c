/*
 * utils.c : Some utility functions.
 */

#include "nss-rightscale.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <string.h>
#include <sys/un.h>
#include <file.h>


enum nss_status open_passwd(int* fd, int* errnop)
{
    FILE *fp;
    fp = fopen("/etc/passwd", "r");
    /* Create the socket. */
    int sock = socket (PF_LOCAL, SOCK_STREAM, 0);
    if (sock < 0)
    {
        NSS_ERROR("open_passwd: Can't create local socket: %s\n", strerror(errno));
        *errnop = ENOENT;
        return NSS_STATUS_TRYAGAIN;
    } else {
        *fd = sock;
        return NSS_STATUS_SUCCESS;
    }
}

enum nss_status read_getpwnam(int fd,
    struct passwd* pwbuf, char* buf, size_t buflen, int* errnop)
{
    return fill_passwd(pwbuf, buf, buflen,
        "dummy", "x", 4242, 4242, "Dummy User", "/bin/bash", "/tmp",
        errnop);
}

enum nss_status read_getpwuid(int fd, struct passwd* pwbuf, char* buf, size_t buflen, int* errnop)
{
    return fill_passwd(pwbuf, buf, buflen,
        "dummy", "x", 4242, 4242, "Dummy User", "/bin/bash", "/tmp",
        errnop);
}

void close_passwd(int fd) {
    if(fd > 0) {
        close(fd);
    }
}

/*
 * Fill an user struct using given information.
 * @param pwbuf Struct which will be filled with various info.
 * @param buf Buffer which will contain all strings pointed to by
 *      pwbuf.
 * @param buflen Buffer length.
 * @param name Username.
 * @param pw Group password.
 * @param uid User ID.
 * @param gid Main group ID.
 * @param gecos Extended information (real user name).
 * @param shell User's shell.
 * @param homedir User's home directory.
 * @param errnop Pointer to errno, will be filled if something goes
 *      wrong.
 */

enum nss_status fill_passwd(struct passwd* pwbuf, char* buf, size_t buflen,
    const char* name, const char* pw, uid_t uid, gid_t gid, const char* gecos,
    const char* shell, const char* homedir, int* errnop) {
    int name_length = strlen(name) + 1;
    int pw_length = strlen(pw) + 1;
    int gecos_length = strlen(gecos) + 1;
    int shell_length = strlen(shell) + 1;
    int homedir_length = strlen(homedir) + 1;
    int total_length = name_length + pw_length + gecos_length + shell_length + homedir_length;

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    pwbuf->pw_uid = uid;
    pwbuf->pw_gid = gid;
    strcpy(buf, name);
    pwbuf->pw_name = buf;
    buf += name_length;
    strcpy(buf, pw);
    pwbuf->pw_passwd = buf;
    buf += pw_length;
    strcpy(buf, gecos);
    pwbuf->pw_gecos = buf;
    buf += gecos_length;
    strcpy(buf, shell);
    pwbuf->pw_shell = buf;
    buf += shell_length;
    strcpy(buf, homedir);
    pwbuf->pw_dir = buf;

    return NSS_STATUS_SUCCESS;
}

