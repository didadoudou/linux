/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __USB_FUZZER_GADGET_H
#define __USB_FUZZER_GADGET_H

#include <linux/types.h>
#include <linux/usb/ch9.h>

struct usb_fuzzer_gadget_response {
	u16 length;
	void *data;

	enum usb_device_state state;
	unsigned power;
};

struct usb_fuzzer_gadget_info {
	enum usb_device_speed speed;

	void *user_data;
	void (*setup)(void *user_data, const struct usb_ctrlrequest *,
			struct usb_fuzzer_gadget_response *);
};

void *usb_fuzzer_gadget_init(struct usb_fuzzer_gadget_info *info);
int usb_fuzzer_gadget_run(void *gadget);
int usb_fuzzer_gadget_stop(void *gadget);
void usb_fuzzer_gadget_destroy(void *gadget);

#endif
