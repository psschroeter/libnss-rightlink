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


/*
 * struct used to store data used by getpwent.
 */
static struct {
    FILE* fp;
    /*  flag to know if NSS_TRYAGAIN
        was returned by previous call
        to getpwent_r */
    int try_again;
    int line_no;
    /* user information cache used if NSS_TRYAGAIN was returned */
    struct passwd* entry;
} pwent_data = { NULL, FALSE, 1, NULL};

/**
 * Setup everything needed to retrieve passwd entries.
 */
enum nss_status _nss_rightscale_setpwent() {
    NSS_DEBUG("rightscale setpwent\n");
    if (pwent_data.fp == NULL) {
        pwent_data.fp = open_policy_file();
        if (pwent_data.fp == NULL) {
            return NSS_STATUS_UNAVAIL;
        }
        pwent_data.line_no = 1;
    }
    return NSS_STATUS_SUCCESS;
}

/*
 * Free getpwent resources.
 */
enum nss_status _nss_rightscale_endpwent() {
    NSS_DEBUG("rightscale endpwent\n");
    close_policy_file(pwent_data.fp);
    return NSS_STATUS_SUCCESS;
}

/*
 * Return next passwd entry.
 */
enum nss_status _nss_rightscale_getpwent_r(struct passwd *pwbuf, char *buf,
            size_t buflen, int *errnop) {

    int res;
    enum nss_status set_status;
    NSS_DEBUG("rightscale getpwent_r\n");
    if (pwent_data.fp == NULL) {
        set_status = _nss_rightscale_setpwent();
        if (set_status != NSS_STATUS_SUCCESS) {
            *errnop = ENOENT;
            return set_status;
        }
    }

    if(pwent_data.try_again) {
        res = fill_passwd(pwbuf, buf, buflen, pwent_data.entry, errnop);
        /* buffer was long enough this time */
        if(!(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE)) {
            pwent_data.try_again = FALSE;
            free_passwd(pwent_data.entry);
            return res;
        }
    }
    while (pwent_data.entry = read_next_policy_entry(pwent_data.fp, &pwent_data.line_no)) {
        if (pwent_data.entry != NULL) {
            res = fill_passwd(pwbuf, buf, buflen, pwent_data.entry, errnop);
            if(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE) {
                pwent_data.try_again = TRUE;
            } else {
                free_passwd(pwent_data.entry);
            }
            return res;
        } else {
            return NSS_STATUS_NOTFOUND;
        }
    }
}

/**
 * Get user info by username.
 */
enum nss_status _nss_rightscale_getpwnam_r(const char* name, struct passwd *pwbuf,
            char *buf, size_t buflen, int *errnop) {
    int res;
    struct passwd* entry;

    NSS_DEBUG("rightscale getpwnam_r: Looking for user %s\n", name);

    FILE *fp = open_policy_file();
    if (fp == NULL) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    int found = FALSE;
    int line_no = 1;
    while (entry = read_next_policy_entry(fp, &line_no)) {
        if (strcmp(entry->pw_name, name) == 0) {
            found = TRUE;
            res = fill_passwd(pwbuf, buf, buflen, entry, errnop);
            break;
        }
        free_passwd(entry);
    }

    /* We've gotten to the end of file without finding anything */
    if (!found) {
        res = NSS_STATUS_NOTFOUND;
        *errnop = ENOENT;
    }

    close_policy_file(fp);
    return res;
}

/*
 * Get user by UID.
 */
enum nss_status _nss_rightscale_getpwuid_r(uid_t uid, struct passwd *pwbuf,
               char *buf, size_t buflen, int *errnop) {
    int res;
    struct passwd* entry;

    NSS_DEBUG("rightscale getpwnam_r: Looking for uid %d\n", uid);

    FILE *fp = open_policy_file();
    if (fp == NULL) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    int found = FALSE;
    int line_no = 1;
    while (entry = read_next_policy_entry(fp, &line_no)) {
        if (entry->pw_uid == uid) {
            found = TRUE;
            res = fill_passwd(pwbuf, buf, buflen, entry, errnop);
            break;
        }

        free_passwd(entry);
    }

    /* We've gotten to the end of file without finding anything */
    if (!found) {
        res = NSS_STATUS_NOTFOUND;
        *errnop = ENOENT;
    }

    close_policy_file(fp);
    return res;
}


