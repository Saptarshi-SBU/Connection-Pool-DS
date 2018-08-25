/* Stats
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef __STAT_H
#define __STAT_H

#include <linux/ktime.h>

static inline unsigned long div64_safe(unsigned long sum, unsigned long nr)
{
	return nr ? div64_ul(sum, nr) : 0;
}

static inline u64 jiffies_now(void)
{
	return get_jiffies_64();
}

static inline s64 ktime_ns_delta(const ktime_t later, const ktime_t earlier)
{
    return ktime_to_ns(ktime_sub(later, earlier));
}

#ifdef CONFIG_CACHEOBJS_STATS

static inline void cacheobjects_stat(atomic_t *stat)
{
        atomic_inc(stat);
}

static inline void cacheobjects_stat_d(atomic_t *stat)
{
        atomic_dec(stat);
}

static inline void cacheobjects_stat64_reset(atomic64_t *stat)
{
	atomic64_set(stat, 0);
}

static inline void cacheobjects_stat64(atomic64_t *stat)
{
        atomic64_inc(stat);
}

static inline void cacheobjects_stat64_d(atomic64_t *stat)
{
        atomic64_dec(stat);
}

static inline void cacheobjects_stat64_add(long i, atomic64_t *stat)
{
        atomic64_add(i, stat);
}

static inline s64 cacheobjects_stat64_read(atomic64_t *stat)
{
	return atomic64_read(stat);
}

static inline void cacheobjects_stat64_jiffies(unsigned long *now)
{
	*now = jiffies_now();
}

static inline u64 cacheobjects_stat64_jiffies2usec(atomic64_t *stat)
{
	return jiffies64_to_nsecs(atomic64_read(stat))/1000UL;
}

static inline void cacheobjects_stat64_ktime(ktime_t *now)
{
        *now = ktime_get();
}

#define INITIALIZE_STATS_CONFIG(value, newvalue) \
 (value) = (newvalue)

#else
#define cacheobjects_stat(stat) do {} while (0)
#define cacheobjects_stat_d(stat) do {} while (0)
#define cacheobjects_stat64_reset(stat) do {} while (0)
#define cacheobjects_stat64(stat) do {} while (0)
#define cacheobjects_stat64_d(stat) do {} while (0)
#define cacheobjects_stat64_add(x, stat) do {} while (0)
#define cacheobjects_stat64_read(stat) 0
#define cacheobjects_stat64_jiffies(stat) do {} while (0)
#define cacheobjects_stat64_jiffies2usec(stat) 0
#define cacheobjects_stat64_ktime(stat) do {} while (0)
#define INITIALIZE_STATS_CONFIG(value, newvalue) do {} while (0)

#endif

#endif

