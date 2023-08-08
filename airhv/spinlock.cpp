#include <ntddk.h>
#include "spinlock.h"

// This implementation is derived from Hvpp by Petr Benes
//  - https://github.com/wbenny/hvpp
// Based on my benchmarks, this simple implementation beats other (often
// more complex) spinlock implementations - such as queue spinlocks, ticket
// spinlocks, MCS locks.  The only difference between this implementation
// and completely naive spinlock is the "backoff".
//
// Also, benefit of this implementation is that we can use it with
// STL lock guards, e.g.: std::lock_guard.
//
// Look here for more information:
//   - https://locklessinc.com/articles/locks/
//   - https://github.com/cyfdecyf/spinlock

static unsigned max_wait = 65536;

spinlock::spinlock(volatile long* _lock) : m_lock(_lock)
{
	lock();
}

spinlock::~spinlock()
{
	unlock();
}

bool spinlock::try_lock()
{
	return (!(*m_lock) && !_interlockedbittestandset(m_lock, 0));
}

void spinlock::lock()
{
	unsigned __int32 wait = 1;

	while (!try_lock())
	{
		for (unsigned __int32 i = 0; i < wait; ++i)
		{
			_mm_pause();
		}

		// Don't call "pause" too many times. If the wait becomes too big,
		// clamp it to the max_wait.

		if (wait * 2 > max_wait)
		{
			wait = max_wait;
		}
		else
		{
			wait = wait * 2;
		}
	}
}

void spinlock::unlock()
{
	*m_lock = 0;
}