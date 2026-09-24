/* passkey-u2f USER [pam_u2f options...]
 *
 * Runs pam_u2f for USER in a fresh process and writes "y" to fd 3 when the
 * device approved. pam_passkey starts it next to the password prompt; being
 * exec'd, it shares no locks or threads with the program asking. */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef int (*auth_fn)(pam_handle_t *, int, int, const char **);

static const char *const DIRS[] = {
    "/usr/lib/security", "/lib/security", "/usr/lib64/security", "/lib64/security",
    "/usr/lib/x86_64-linux-gnu/security", "/lib/x86_64-linux-gnu/security",
    "/usr/lib/aarch64-linux-gnu/security", "/lib/aarch64-linux-gnu/security", NULL,
};

/* No prompts: the password is pam_passkey's business. Messages are fine. */
static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
    for (int i = 0; i < n; i++)
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
            return PAM_CONV_ERR;
    *resp = NULL;
    return PAM_SUCCESS;
}

int main(int argc, char **argv) {
    struct pam_conv c = { conv, NULL };
    pam_handle_t *pamh;
    auth_fn fn = NULL;
    char so[512];

    if (argc < 2) return 2;
    for (int i = 0; DIRS[i] && !fn; i++) {
        void *h;
        snprintf(so, sizeof so, "%s/pam_u2f.so", DIRS[i]);
        if ((h = dlopen(so, RTLD_NOW | RTLD_LOCAL)))
            fn = (auth_fn) dlsym(h, "pam_sm_authenticate");
    }
    if (!fn || pam_start("passkey-u2f", argv[1], &c, &pamh) != PAM_SUCCESS) return 1;
    if (fn(pamh, PAM_SILENT, argc - 2, (const char **) argv + 2) != PAM_SUCCESS) return 1;
    return write(3, "y", 1) == 1 ? 0 : 1;
}
