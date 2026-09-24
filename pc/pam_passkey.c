/* pam_passkey: password and fingerprint at the same time.
 *
 * Asks for the password as usual while a helper process (passkey-u2f, which
 * runs pam_u2f) waits for the fingerprint on the Android device. Whichever
 * comes first wins:
 *   - fingerprint approved   -> PAM_SUCCESS (a password prompt still waiting
 *                               on the terminal is ended with a newline)
 *   - password typed         -> the fingerprint request is withdrawn and the
 *                               password goes to the next module as PAM_AUTHTOK
 *                               (pam_unix try_first_pass); result PAM_IGNORE
 *   - empty password (Enter) -> wait for the fingerprint (asking again if the
 *                               first request already ended)
 * With no device connected, or no key registered for the user, it steps
 * aside at once and the stack behaves exactly as without it.
 *
 * Options of its own (the rest go to pam_u2f unchanged):
 *   mode=parallel   ask the device right away (sudo, polkit, text login)
 *   mode=on-empty   ask it only after Enter on an empty field (lock and login
 *                   screens, which show their own password field)
 *   helper=PATH     the helper (default HELPER, set by the Makefile)
 */
#define _GNU_SOURCE
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define HID_ID "HID_ID=0003:00001209:00007AB1"
#define MAX_ARGS 32
#define ASK_SECONDS 45          /* the device gives up after 30 s */
#ifndef HELPER
#define HELPER "/usr/local/lib/passkey/passkey-u2f"
#endif

/* A passkey device is plugged in (the companion only creates it while the
 * Android device is connected). */
static int device_present(void) {
    DIR *d = opendir("/sys/class/hidraw");
    struct dirent *e;
    int found = 0;
    if (!d) return 0;
    while (!found && (e = readdir(d))) {
        char path[PATH_MAX], line[256];
        FILE *f;
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof path, "/sys/class/hidraw/%s/device/uevent", e->d_name);
        if (!(f = fopen(path, "r"))) continue;
        while (fgets(line, sizeof line, f))
            if (!strncmp(line, HID_ID, strlen(HID_ID))) { found = 1; break; }
        fclose(f);
    }
    closedir(d);
    return found;
}

static int user_registered(const char *authfile, const char *user) {
    FILE *f = fopen(authfile, "r");
    char *line = NULL;
    size_t cap = 0, n = strlen(user);
    int found = 0;
    if (!f) return 0;
    while (!found && getline(&line, &cap, f) > 0)
        found = !strncmp(line, user, n) && line[n] == ':' && line[n + 1] && line[n + 1] != '\n';
    free(line);
    fclose(f);
    return found;
}

/* ---- password prompt on its own thread ---------------------------------- */
struct prompt {
    pam_handle_t *pamh;
    const char *text;
    int fd;             /* write end: one byte when done */
    int rc;
    char *answer;
};

static void *prompt_thread(void *arg) {
    struct prompt *p = arg;
    p->rc = pam_prompt(p->pamh, PAM_PROMPT_ECHO_OFF, &p->answer, "%s", p->text);
    if (write(p->fd, "x", 1) < 0) { /* the reader is gone; nothing to do */ }
    return NULL;
}

/* ---- the fingerprint request: a helper process ---------------------------- */
struct ask {
    pid_t pid;
    int pidfd;          /* -1 if the kernel has no pidfd_open */
    int result;         /* read end: "y" then EOF on approval, just EOF otherwise */
    time_t deadline;
};

/* fork + exec only: the host may have other threads holding locks, so the
 * child runs nothing but async-signal-safe calls before exec. The helper
 * writes "y" to fd 3; exit statuses are not used because the host may reap
 * its children itself. */
static int ask_start(struct ask *a, const char *helper, const char *user, int argc, const char **argv) {
    const char *args[MAX_ARGS + 3];
    int p[2], n = 0;
    args[n++] = helper;
    args[n++] = user;
    for (int i = 0; i < argc; i++) args[n++] = argv[i];
    args[n] = NULL;
    if (pipe2(p, O_CLOEXEC) < 0) return -1;
    a->pid = fork();
    if (a->pid == 0) {
        if (dup2(p[1], 3) < 0) _exit(1);
        execv(helper, (char *const *) args);
        _exit(1);
    }
    close(p[1]);
    if (a->pid < 0) { close(p[0]); return -1; }
    a->result = p[0];
    a->pidfd = (int) syscall(SYS_pidfd_open, a->pid, 0);
    a->deadline = time(NULL) + ASK_SECONDS;
    return 0;
}

/* Ends the request: the helper dies, the device node closes, and the
 * companion withdraws the prompt on the device. */
static void ask_stop(struct ask *a) {
    if (a->result < 0) return;
    if (a->pidfd >= 0) syscall(SYS_pidfd_send_signal, a->pidfd, SIGKILL, NULL, 0);
    else kill(a->pid, SIGKILL);
    waitpid(a->pid, NULL, 0);           /* may fail if the host reaps; harmless */
    if (a->pidfd >= 0) close(a->pidfd);
    close(a->result);
    a->result = a->pidfd = -1;
}

/* Ends a password prompt that is really waiting on this terminal (echo off),
 * by typing Enter into it. Needs CAP_SYS_ADMIN, which sudo and login have
 * while authenticating; elsewhere it quietly does nothing. */
static void end_tty_prompt(void) {
    struct termios t;
    char nl = '\n';
    int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return;
    if (!tcgetattr(fd, &t) && !(t.c_lflag & ECHO)) ioctl(fd, TIOCSTI, &nl);
    close(fd);
}

static void wipe(char *s) {
    if (s) { explicit_bzero(s, strlen(s)); free(s); }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *u2f_argv[MAX_ARGS], *user = NULL, *authfile = NULL;
    const char *helper = HELPER;
    int u2f_argc = 0, on_empty = 0;

    for (int i = 0; i < argc && u2f_argc < MAX_ARGS; i++) {
        if (!strcmp(argv[i], "mode=on-empty")) { on_empty = 1; continue; }
        if (!strcmp(argv[i], "mode=parallel")) continue;
        if (!strncmp(argv[i], "helper=", 7)) { helper = argv[i] + 7; continue; }
        if (!strncmp(argv[i], "authfile=", 9)) authfile = argv[i] + 9;
        u2f_argv[u2f_argc++] = argv[i];
    }
    if (!authfile || access(helper, X_OK) || pam_get_user(pamh, &user, NULL) != PAM_SUCCESS
        || !user || !device_present() || !user_registered(authfile, user))
        return PAM_IGNORE;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) return PAM_IGNORE;

    struct ask a = { -1, -1, -1, 0 };
    int tries = 0;
    if (!on_empty && !ask_start(&a, helper, user, u2f_argc, u2f_argv)) tries++;

    /* On the heap: if a GUI prompt is still open when the key wins, its thread
     * outlives this call (the process ends right after), so it is leaked. */
    struct prompt *pr = calloc(1, sizeof *pr);
    if (!pr) { close(pipefd[0]); close(pipefd[1]); ask_stop(&a); return PAM_IGNORE; }
    *pr = (struct prompt) { pamh, on_empty ? "Password: " : "Password (or confirm on your device): ",
                            pipefd[1], PAM_CONV_ERR, NULL };
    pthread_t tid;
    int prompting = !pthread_create(&tid, NULL, prompt_thread, pr), detached = 0;
    int result = PAM_IGNORE;

    /* Signals go to the prompt thread, so ^C at the prompt works as usual. */
    sigset_t block, old;
    sigfillset(&block);
    pthread_sigmask(SIG_BLOCK, &block, &old);

    for (;;) {
        struct pollfd fds[2] = { { prompting ? pipefd[0] : -1, POLLIN, 0 }, { a.result, POLLIN, 0 } };
        if (!prompting && a.result < 0) break;
        int wait_ms = -1;
        if (a.result >= 0) {
            long left = (long) (a.deadline - time(NULL));
            wait_ms = left > 0 ? (int) left * 1000 : 0;
        }
        int n = poll(fds, 2, wait_ms);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) {                              /* the device never answered */
            ask_stop(&a);
            if (!prompting) break;
            continue;
        }

        if (prompting && fds[0].revents) {         /* the password prompt returned */
            char c;
            if (read(pipefd[0], &c, 1) < 0) { /* treated like a finished prompt */ }
            pthread_join(tid, NULL);
            prompting = 0;
            if (pr->rc != PAM_SUCCESS || !pr->answer) {    /* ^C or a broken conversation */
                result = pr->rc == PAM_SUCCESS ? PAM_CONV_ERR : pr->rc;
                break;
            }
            if (pr->answer[0]) {                         /* a password: that path wins */
                pam_set_item(pamh, PAM_AUTHTOK, pr->answer);
                result = PAM_IGNORE;
                break;
            }
            /* Empty: the user wants the fingerprint. Ask the device (again). */
            if (a.result < 0 && tries < 3) {
                pam_info(pamh, "Confirm with your fingerprint on your device.");
                if (!ask_start(&a, helper, user, u2f_argc, u2f_argv)) tries++;
            }
            if (a.result < 0) break;
            continue;                              /* the helper may have answered too */
        }

        if (fds[1].revents) {                      /* the helper finished */
            char ok = 0;
            int approved = read(a.result, &ok, 1) == 1 && ok == 'y';
            ask_stop(&a);
            if (!approved) {
                if (!prompting) break;             /* Enter was pressed, the key said no */
                continue;                          /* the password prompt is still open */
            }
            result = PAM_SUCCESS;
            if (prompting) {
                end_tty_prompt();
                struct pollfd w = { pipefd[0], POLLIN, 0 };
                if (poll(&w, 1, 1000) > 0) pthread_join(tid, NULL);
                else { pthread_detach(tid); detached = 1; }   /* a GUI prompt; its process ends soon */
                prompting = 0;
            }
            break;
        }
    }

    pthread_sigmask(SIG_SETMASK, &old, NULL);
    ask_stop(&a);
    if (prompting) { pthread_detach(tid); detached = 1; }
    if (detached) return result;       /* the thread still owns pr and both pipe ends */
    wipe(pr->answer);
    free(pr);
    close(pipefd[0]);
    close(pipefd[1]);
    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
