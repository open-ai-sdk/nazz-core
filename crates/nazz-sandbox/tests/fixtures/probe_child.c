#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void report_open(const char *label, const char *path, int flags) {
    int fd = open(path, flags, 0644);
    printf("%s=%s\n", label, fd >= 0 ? "allowed" : "denied");
    if (fd >= 0) {
        if ((flags & O_ACCMODE) != O_RDONLY) {
            (void)write(fd, "ok", 2);
        }
        close(fd);
    }
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--flood") == 0) {
        char block[4096];
        memset(block, 'A', sizeof block);
        for (int i = 0; i < 64; i++) {
            if (write(1, block, sizeof block) < 0) {
                return 1;
            }
        }
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "--sleep") == 0) {
        sleep(30);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "--marker") == 0) {
        if (argc < 3) {
            return 2;
        }
        int fd = open(argv[2], O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) {
            return 1;
        }
        (void)write(fd, "spawned", 7);
        close(fd);
        return 0;
    }
    if (argc < 12) {
        fprintf(stderr, "usage: probe grant unrelated unix ssh port profile exe other symlink_read symlink_write marker_out\n");
        return 2;
    }
    char owned[1024];
    snprintf(owned, sizeof owned, "%s/owned.txt", argv[1]);
    report_open("grant_write", owned, O_CREAT | O_WRONLY | O_TRUNC);
    report_open("unrelated_file", argv[2], O_RDONLY);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in in;
    memset(&in, 0, sizeof in);
    in.sin_family = AF_INET;
    in.sin_port = htons((unsigned short)atoi(argv[5]));
    inet_pton(AF_INET, "127.0.0.1", &in.sin_addr);
    printf("tcp=%s\n", (tcp >= 0 && connect(tcp, (struct sockaddr *)&in, sizeof in) == 0) ? "allowed" : "denied");
    if (tcp >= 0) {
        close(tcp);
    }
    int unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un un;
    memset(&un, 0, sizeof un);
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, argv[3], sizeof un.sun_path - 1);
    printf("unix=%s\n", (unix_fd >= 0 && connect(unix_fd, (struct sockaddr *)&un, sizeof un) == 0) ? "allowed" : "denied");
    if (unix_fd >= 0) {
        close(unix_fd);
    }
    int agent = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un ag;
    memset(&ag, 0, sizeof ag);
    ag.sun_family = AF_UNIX;
    strncpy(ag.sun_path, argv[4], sizeof ag.sun_path - 1);
    printf("ssh_agent=%s\n", (agent >= 0 && connect(agent, (struct sockaddr *)&ag, sizeof ag) == 0) ? "allowed" : "denied");
    if (agent >= 0) {
        close(agent);
    }
    const char *env = getenv("NAZZ_PARENT_CANARY");
    printf("env=%s\n", env ? env : "absent");
    printf("ssh_env=%s\n", getenv("SSH_AUTH_SOCK") ? "present" : "absent");
    printf("home=%s\n", getenv("HOME") ? "present" : "absent");
    const char *path = getenv("PATH");
    printf("path=%s\n", path ? path : "absent");
    report_open("profile_write", argv[6], O_WRONLY | O_TRUNC);
    report_open("exec_write", argv[7], O_WRONLY | O_TRUNC);
    report_open("symlink_read", argv[9], O_RDONLY);
    report_open("symlink_write", argv[10], O_WRONLY | O_TRUNC);
    char made[1024];
    snprintf(made, sizeof made, "%s/made", argv[1]);
    if (symlink(argv[2], made) != 0) {
        printf("symlink_create=denied\n");
        printf("made_symlink_read=denied\n");
    } else {
        printf("symlink_create=allowed\n");
        int fd = open(made, O_RDONLY);
        printf("made_symlink_read=%s\n", fd >= 0 ? "allowed" : "denied");
        if (fd >= 0) {
            close(fd);
        }
    }
    pid_t pid = 0;
    char *av[] = {argv[8], "--marker", argv[11], NULL};
    int rc = posix_spawn(&pid, argv[8], NULL, NULL, av, NULL);
    printf("other_exec=%s\n", rc == 0 ? "allowed" : "denied");
    if (rc == 0) {
        int st = 0;
        waitpid(pid, &st, 0);
    }
    return 0;
}
