/*
 * test_69_sysv_ipc.c — System V IPC sandbox escape vectors
 *
 * System V IPC (shared memory, semaphores, message queues) can cross
 * namespace boundaries and provide communication channels between
 * sandboxed and unsandboxed processes.
 *
 * - shmget/shmat: Shared memory segments persist across processes
 * - semget/semop: Semaphores for cross-process synchronization
 * - msgget/msgsnd/msgrcv: Message queues for data exfiltration
 * - shmctl IPC_INFO: Information leak about system IPC limits
 *
 * Tests:
 *  1. shmget — create shared memory segment
 *  2. shmat — attach to shared memory
 *  3. shmctl IPC_INFO — system IPC info leak
 *  4. semget — create semaphore set
 *  5. semop — semaphore operation
 *  6. msgget — create message queue
 *  7. msgsnd — send message
 *  8. msgrcv — receive message
 */
#include "test_harness.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>

struct msgbuf_local {
    long mtype;
    char mtext[64];
};

int main(void) {
    install_sigsys_handler();

    PRINT_HEADER("SYSTEM V IPC ESCAPE VECTORS");

    /* Test 1: shmget — create shared memory */
    {
        g_got_sigsys = 0;
        int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
        int blocked = (shmid < 0 || g_got_sigsys);
        if (shmid >= 0) shmctl(shmid, IPC_RMID, NULL);

        TEST("shmget(IPC_PRIVATE) blocked",
             blocked,
             blocked ? "blocked" :
             "SHMGET — shared memory segment created from sandbox!");
    }

    /* Test 2: shmat — attach shared memory */
    {
        g_got_sigsys = 0;
        int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
        int attached = 0;
        if (shmid >= 0) {
            void *ptr = shmat(shmid, NULL, 0);
            if (ptr != (void *)-1) {
                attached = 1;
                shmdt(ptr);
            }
            shmctl(shmid, IPC_RMID, NULL);
        }

        TEST("shmat attachment blocked",
             !attached || g_got_sigsys,
             attached ? "SHMAT — shared memory attached from sandbox!" :
             "blocked");
    }

    /* Test 3: shmctl IPC_INFO — information leak */
    {
        g_got_sigsys = 0;
        struct shminfo info;
        memset(&info, 0, sizeof(info));
        int ret = shmctl(0, IPC_INFO, (struct shmid_ds *)&info);
        int blocked = (ret < 0 || g_got_sigsys);

        TEST("shmctl(IPC_INFO) blocked",
             blocked,
             blocked ? "blocked" :
             "IPC INFO — system SHM limits readable from sandbox!");
    }

    /* Test 4: semget — create semaphore set */
    {
        g_got_sigsys = 0;
        int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
        int blocked = (semid < 0 || g_got_sigsys);
        if (semid >= 0) semctl(semid, 0, IPC_RMID);

        TEST("semget(IPC_PRIVATE) blocked",
             blocked,
             blocked ? "blocked" :
             "SEMGET — semaphore set created from sandbox!");
    }

    /* Test 5: semop — semaphore operation */
    {
        g_got_sigsys = 0;
        int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
        int operated = 0;
        if (semid >= 0) {
            /* Initialize semaphore value */
            semctl(semid, 0, SETVAL, 1);

            struct sembuf sop = {
                .sem_num = 0,
                .sem_op = -1,  /* P operation (decrement) */
                .sem_flg = IPC_NOWAIT,
            };
            int ret = semop(semid, &sop, 1);
            operated = (ret == 0);
            semctl(semid, 0, IPC_RMID);
        }

        TEST("semop operation blocked",
             !operated || g_got_sigsys,
             operated ? "SEMOP — semaphore operated from sandbox!" :
             "blocked");
    }

    /* Test 6: msgget — create message queue */
    {
        g_got_sigsys = 0;
        int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
        int blocked = (msqid < 0 || g_got_sigsys);
        if (msqid >= 0) msgctl(msqid, IPC_RMID, NULL);

        TEST("msgget(IPC_PRIVATE) blocked",
             blocked,
             blocked ? "blocked" :
             "MSGGET — message queue created from sandbox!");
    }

    /* Test 7: msgsnd — send message */
    {
        g_got_sigsys = 0;
        int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
        int sent = 0;
        if (msqid >= 0) {
            struct msgbuf_local msg;
            msg.mtype = 1;
            strncpy(msg.mtext, "sandbox_escape_test", sizeof(msg.mtext));
            int ret = msgsnd(msqid, &msg, sizeof(msg.mtext), IPC_NOWAIT);
            sent = (ret == 0);
            msgctl(msqid, IPC_RMID, NULL);
        }

        TEST("msgsnd message blocked",
             !sent || g_got_sigsys,
             sent ? "MSGSND — message sent from sandbox!" :
             "blocked");
    }

    /* Test 8: msgrcv — receive message */
    {
        g_got_sigsys = 0;
        int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
        int received = 0;
        if (msqid >= 0) {
            /* Send a message first */
            struct msgbuf_local msg;
            msg.mtype = 1;
            strncpy(msg.mtext, "test", sizeof(msg.mtext));
            msgsnd(msqid, &msg, sizeof(msg.mtext), IPC_NOWAIT);

            /* Try to receive */
            struct msgbuf_local rcv;
            ssize_t n = msgrcv(msqid, &rcv, sizeof(rcv.mtext), 1, IPC_NOWAIT);
            received = (n > 0);
            msgctl(msqid, IPC_RMID, NULL);
        }

        TEST("msgrcv receive blocked",
             !received || g_got_sigsys,
             received ? "MSGRCV — message received from sandbox!" :
             "blocked");
    }

    PRINT_SUMMARY();
    return g_fail ? 1 : 0;
}
