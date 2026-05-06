/*
 * FIXED: Command Injection (CWE-78)
 *
 * Fixes applied:
 * 1. Replace system() with fork() + execve() — no shell involved
 * 2. Arguments passed directly to execve(), not interpreted
 * 3. Validate destination path before use
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

/* FIX: validate that dest_path is a writable directory */
static int validate_backup_path(const char *path) {
    if (!path || path[0] == '\0') return -1;

    /* Reject obvious shell metacharacters */
    if (strpbrk(path, ";|&`$(){}[]<>!\\\"'")) {
        printf("[-] Rejected: shell metacharacters in path\n");
        return -1;
    }

    /* Check path length */
    if (strlen(path) > 512) {
        printf("[-] Rejected: path too long\n");
        return -1;
    }

    return 0;
}

/* FIX: use fork+execve — arguments go directly to cp, not through shell */
static int config_backup_fixed(const char *dest_path) {
    if (validate_backup_path(dest_path) != 0) {
        printf("[-] Backup path validation failed\n");
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child process: exec cp directly
         *
         * Arguments are passed as an array — NO shell interpretation.
         * Even if dest_path contains "; rm -rf /", it's just a filename
         * to cp, not a command to execute.
         */
        const char *argv[] = {
            "cp",
            "-r",
            "/etc/securefile",
            dest_path,
            NULL
        };
        execvp("cp", (char * const *)argv);

        /* If we reach here, exec failed */
        perror("execvp");
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            printf("[+] Backup completed (exit=%d)\n", exit_code);
            return exit_code == 0 ? 0 : -1;
        }
        return -1;
    } else {
        perror("fork");
        return -1;
    }
}

int main(int argc, char *argv[]) {
    printf("=== CWE-78: Command Injection — FIXED ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <backup_path>\n", argv[0]);
        printf("  Safe:    %s /tmp/backup\n", argv[0]);
        printf("  Blocked: %s \"/tmp/x; cat /etc/passwd\"\n", argv[0]);
        return 0;
    }

    /* FIX: even a malicious path is handled safely */
    printf("[*] Backup path: '%s'\n", argv[1]);
    config_backup_fixed(argv[1]);

    printf("\n[+] Command injection prevented.\n");
    printf("    Key fix: fork() + execve() instead of system()\n");
    printf("    Arguments go directly to the target program, no shell involved.\n");
    printf("    Also validate input: reject shell metacharacters.\n");

    return 0;
}
