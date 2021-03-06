#ifndef NSS_RIGHTSCALE_H
#define NSS_RIGHTSCALE_H

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
/* #error You must use autotools to build this! */
#endif

#include <nss.h>
#include <syslog.h>
#include <stdio.h>

/* Some syslog shortcuts */
#ifdef DEBUG
#define NSS_DEBUG(msg, ...) printf((msg), ## __VA_ARGS__)
/* #define NSS_DEBUG(msg, ...) syslog(LOG_INFO, (msg), ## __VA_ARGS__) */
#else
#define NSS_DEBUG(msg, ...)
#endif

#define NSS_ERROR(msg, ...) syslog(LOG_ERR, (msg), ## __VA_ARGS__)

#define FALSE 0
#define TRUE !FALSE

#endif
