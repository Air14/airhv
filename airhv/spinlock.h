#pragma once

class spinlock
{
public:
    spinlock(volatile long* _lock);
    ~spinlock();
private:
    bool try_lock();
    void lock();
    void unlock();

    volatile long* m_lock;
};