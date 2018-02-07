/*
 * Multi-device Header file.
 *
 * Copyright (c) 2018 NetApp Inc. All rights reserved.
 *
 * ZUFS-License: GPL-2.0 OR BSD-3-Clause. See module.c for LICENSE details.
 *
 * Authors:
 *	Boaz Harrosh <boazh@netapp.com>
 */

#ifndef __RELAY_H__
#define __RELAY_H__

/* ~~~~ Relay ~~~~ */
struct relay {
	wait_queue_head_t fss_wq;
	volatile bool fss_wakeup;
	volatile bool fss_waiting;

	wait_queue_head_t app_wq;
	volatile bool app_wakeup;
	volatile bool app_waiting;
};

static inline void relay_init(struct relay *relay)
{
	init_waitqueue_head(&relay->fss_wq);
	init_waitqueue_head(&relay->app_wq);
}

static inline void relay_fss_waiting_grab(struct relay *relay)
{
	relay->fss_waiting = true;
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

static inline int relay_fss_wait(struct relay *relay)
{
	int err;

	relay->fss_wakeup = false;
	err =  wait_event_interruptible(relay->fss_wq, relay->fss_wakeup);

	relay->fss_waiting = false;
	return err;
}

static inline bool relay_is_fss_waiting(struct relay *relay)
{
	return relay->fss_waiting;
}

static inline void relay_fss_wakeup(struct relay *relay)
{
	relay->fss_wakeup = true;
	wake_up(&relay->fss_wq);
}

static inline int relay_fss_wakeup_app_wait(struct relay *relay,
					    spinlock_t *spinlock)
{
	relay->app_waiting = true;

	relay_fss_wakeup(relay);

	relay->app_wakeup = false;
	if (spinlock)
		spin_unlock(spinlock);

	return wait_event_interruptible(relay->app_wq, relay->app_wakeup);
}

#endif /* ifndef __RELAY_H__ */
