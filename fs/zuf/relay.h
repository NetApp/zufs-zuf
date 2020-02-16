/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Relay scheduler-object Header file.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#ifndef __RELAY_H__
#define __RELAY_H__

/* ~~~~ Relay ~~~~ */
struct relay {
	wait_queue_head_t fss_wq;
	bool fss_wakeup;
	bool fss_waiting;

	wait_queue_head_t app_wq;
	bool app_wakeup;
	bool app_waiting;
};

static inline void relay_init(struct relay *relay)
{
	init_waitqueue_head(&relay->fss_wq);
	init_waitqueue_head(&relay->app_wq);
}

static inline bool relay_is_app_waiting(struct relay *relay)
{
	return relay->app_waiting;
}

static inline void relay_app_wakeup(struct relay *relay)
{
	relay->app_waiting = false;

	relay->app_wakeup = true;
	wake_up(&relay->app_wq);
}

static inline int __relay_fss_wait(struct relay *relay, bool keep_locked)
{
	relay->fss_waiting = !keep_locked;
	relay->fss_wakeup = false;
	return  wait_event_interruptible(relay->fss_wq, relay->fss_wakeup);
}

static inline int relay_fss_wait(struct relay *relay)
{
	return __relay_fss_wait(relay, false);
}

static inline bool relay_is_fss_waiting_grab(struct relay *relay)
{
	if (relay->fss_waiting) {
		relay->fss_waiting = false;
		return true;
	}
	return false;
}

static inline void relay_fss_wakeup(struct relay *relay)
{
	relay->fss_wakeup = true;
	wake_up(&relay->fss_wq);
}

static inline int relay_fss_wakeup_app_wait(struct relay *relay)
{
	relay->app_waiting = true;

	relay_fss_wakeup(relay);

	relay->app_wakeup = false;

	return wait_event_interruptible(relay->app_wq, relay->app_wakeup);
}

static inline
void relay_fss_wakeup_app_wait_spin(struct relay *relay, spinlock_t *spinlock)
{
	relay->app_waiting = true;

	relay_fss_wakeup(relay);

	relay->app_wakeup = false;
	spin_unlock(spinlock);

	wait_event(relay->app_wq, relay->app_wakeup);
}

static inline void relay_fss_wakeup_app_wait_cont(struct relay *relay)
{
	wait_event(relay->app_wq, relay->app_wakeup);
}

#endif /* ifndef __RELAY_H__ */
