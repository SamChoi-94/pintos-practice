< Monitors >
A monitor is a higher-level form of synchronization than a semaphore or a lock. A monitor consists of data being synchronized, plus a lock, called the monitor lock, and one or more condition variables. Before it accesses the protected data, a thread first acquires the monitor lock. It is then said to be "in the monitor". While in the monitor, the thread has control over all the protected data, which it may freely examine or modify. When access to the protected data is complete, it releases the monitor lock.

Condition variables allow code in the monitor to wait for a condition to become true. Each condition variable is associated with an abstract condition, e.g. "some data has arrived for processing" or "over 10 seconds has passed since the user's last keystroke". When code in the monitor needs to wait for a condition to become true, it "waits" on the associated condition variable, which releases the lock and waits for the condition to be signaled. If, on the other hand, it has caused one of these conditions to become true, it "signals" the condition to wake up one waiter, or "broadcasts" the condition to wake all of them.

The theoretical framework for monitors was laid out by C.A.R.Hoare. Their practical usage was later elaborated in a paper on the Mesa operation system. Condition variable types and functions are declared in include/threads/synch.h.

struct condition;
Represents a condition variable.

void cond_init (struct condition *cond);
Initializes cond as a new condition variable.

void cond_wait (struct condition *cond, struct lock *lock);
Atomically releases lock (the monitor lock) and waits for cond to be signaled by some other piece of code. After cond is signaled, reacquires lock before returning. lock must be held before calling this function. Sending a signal and waking up from a wait are not an atomic operation. Thus, typically cond_wait()'s caller must recheck the condition after the wait completes and, if necessary, wait again. See the next section for an example.

void cond_signal (struct condition *cond, struct lock *lock);
If any threads are waiting on cond (protected by monitor lock lock), then this function wakes up one of them. If no threads are waiting, returns without performing any action. lock must be held before calling this function.

void cond_broadcast (struct condition *cond, struct lock *lock);
Wakes up all threads, if any, waiting on cond (protected by monitor lock lock). lock must be held before calling this function.

# Monitor Example
The classical example of a monitor is handling a buffer into which one or more "producer" threads write characters and out of which one or more "consumer" threads read characters. To implement this we need, besides the monitor lock, two condition variables which we will call not_full and not_empty:

    char buf[BUF_SIZE];     /* Buffer. */
    size_t n = 0;         /* 0 <= n <= BUF SIZE: # of characters in buffer. */
    size_t head = 0;        /* buf index of next char to write (mod BUF SIZE). */
    size_t tail = 0;         /* buf index of next char to read (mod BUF SIZE). */
    struct lock lock;         /* Monitor lock. */
    struct condition not_empty; /* Signaled when the buffer is not empty. */
    struct condition not_full;     /* Signaled when the buffer is not full. */

    ...initialize the locks and condition variables...

    void put (char ch) {
      lock_acquire (&lock);
      while (n == BUF_SIZE)    /* Can't add to buf as long as it's full. */
        cond_wait (&not_full, &lock);
      buf[head++ % BUF_SIZE] = ch;    /* Add ch to buf. */
      n++;
      cond_signal (&not_empty, &lock);    /* buf can't be empty anymore. */
      lock_release (&lock);
    }

    char get (void) {
      char ch;
      lock_acquire (&lock);
      while (n == 0)        /* Can't read buf as long as it's empty. */
        cond_wait (&not_empty, &lock);
      ch = buf[tail++ % BUF_SIZE];    /* Get ch from buf. */
      n--;
      cond_signal (&not_full, &lock);    /* buf can't be full anymore. */
      lock_release (&lock);
    }
Note that BUF_SIZE must divide evenly into SIZE_MAX + 1 for the above code to be completely correct. Otherwise, it will fail the first time head wraps around to 0. In practice, BUF_SIZE would ordinarily be a power of 2.

운영체제 동기화 개념 중 모니터 기법에 대한 설명인데, 위 내용을 좀 풀어서 쉽게 나에게 설명해줄래? 설명은 당연히 한국어로 부탁해