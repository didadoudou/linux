#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/uts.h>
#include <linux/wait.h>
#include <linux/compiler.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/mmu_context.h>
#include <linux/aio.h>
#include <linux/uio.h>
#include <linux/refcount.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/moduleparam.h>
#include <linux/debugfs.h>

#include <linux/usb/ch9.h>
#include <linux/usb/ch11.h>
#include <linux/usb/cdc.h>
#include <linux/hid.h>

#include <linux/usb/gadgetfs.h>
#include <linux/usb/gadget.h>

#include "gadget.h"

// TODO: reduce ^

#define	DRIVER_DESC "USB fuzzer"

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR("Andrey Konovalov");
MODULE_LICENSE("GPL");

#if 1
#define print_debug(fmt, args...) pr_err(fmt, ##args)
#else
#define print_debug(fmt, args...)
#endif

/*----------------------------------------------------------------------*/

struct response_map_entry {
	struct response_map_entry	*next;
	char				*data;
	u64				length;
	u8				repeat;
};

struct response_map {
	struct response_map_entry	*heads[0x100];
	struct response_map_entry	*currents[0x100];
};

static int response_add(struct response_map *map, u8 type, char *data, u64 length, u8 repeat)
{
	struct response_map_entry *entry, *new_entry;

	new_entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!new_entry)
		return -ENOMEM;

	new_entry->next = NULL;
	new_entry->data = data;
	new_entry->length = length;
	new_entry->repeat = repeat;

	if (new_entry->repeat == 0)
		new_entry->repeat = 1;
	else
		new_entry->repeat = 2;

	if (!map->heads[type]) {
		map->heads[type] = new_entry;
		map->currents[type] = new_entry;
		return 0;
	}

	for (entry = map->heads[type]; entry->next != NULL; entry = entry->next);
	entry->next = new_entry;

	return 0;
}

static struct response_map_entry *response_next(struct response_map *map, u8 type)
{
	struct response_map_entry *entry = map->currents[type];
	if (!entry)
		return NULL;
	if (--entry->repeat == 0)
		map->currents[type] = entry->next;
	return entry;
}

static void response_free(struct response_map *map)
{
	struct response_map_entry *entry, *next_entry;
	u16 type;

	for (type = 0; type < 0x100; type++) {
		entry = map->heads[type];
		while (entry) {
			next_entry = entry->next;
			kfree(entry->data);
			kfree(entry);
			entry = next_entry;
		}
	}
}

static long response_unpack(struct response_map *map, char *data, u64 length)
{
	long ret = 0;
	u64 offset = 0;
	u64 response_length;
	char *desc;
	u8 type, repeat;

	if (length > 0x10000) {
		ret = -EINVAL;
		goto out;
	}

	while (length > offset) {
		if (length - offset < sizeof(response_length) +
					sizeof(repeat) + sizeof(type)) {
			ret = -EINVAL;
			goto out;
		}
		if (copy_from_user(&response_length, data + offset,
					sizeof(response_length))) {
			ret = -EFAULT;
			goto out;
		}
		offset += sizeof(response_length);
		if (response_length > 0x1000) {
			ret = -EINVAL;
			goto out;
		}
		if (response_length < sizeof(type)) {
			ret = -EINVAL;
			goto out;
		}
		response_length -= sizeof(type);
		if (copy_from_user(&repeat, data + offset, sizeof(repeat))) {
			ret = -EFAULT;
			goto out;
		}
		offset += sizeof(repeat);
		if (copy_from_user(&type, data + offset, sizeof(type))) {
			ret = -EFAULT;
			goto out;
		}
		offset += sizeof(type);
		desc = kmalloc(response_length, GFP_KERNEL);
		if (!desc) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(desc, data + offset, response_length)) {
			kfree(desc);
			ret = -EFAULT;
			goto out;
		}
		offset += response_length;
		ret = response_add(map, type, desc, response_length, repeat);
		if (ret)
			goto out;
		print_debug("uf: response_unpack: found type = %d, length = %llu\n",
				(int)type, response_length);
	}

out:
	return ret;
}

/*----------------------------------------------------------------------*/

enum dev_state {
	STATE_DEV_INVALID = 0,
	STATE_DEV_OPENED,
	STATE_DEV_SETUP,
	STATE_DEV_RUNNING,
	STATE_DEV_CLOSED,
	STATE_DEV_FAILED
};

struct fuzzer_dev {
	spinlock_t			lock;
	enum dev_state			state;
	bool				in_progress;

	void				*gadget;

	char				*dev;
	char				*buf;
	struct response_map		desc_responses;
	struct response_map		req_responses;
	struct response_map		gen_responses;
};

static struct fuzzer_dev *dev_new(void)
{
	struct fuzzer_dev *dev;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;
	spin_lock_init(&dev->lock);
	return dev;
}

static void dev_free(struct fuzzer_dev *dev)
{
	if (dev->dev)
		kfree(dev->dev);
	if (dev->buf)
		kfree(dev->buf);
	response_free(&dev->desc_responses);
	response_free(&dev->req_responses);
	response_free(&dev->gen_responses);
	kfree(dev);
}

static int dev_acquire_state(struct fuzzer_dev *dev, int curr)
{
	spin_lock_irq(&dev->lock);
	if (dev->in_progress || dev->state != curr) {
		spin_unlock_irq(&dev->lock);
		return -EBUSY;
	}
	dev->in_progress = true;
	spin_unlock_irq(&dev->lock);
	return 0;
}

static void dev_release_state(struct fuzzer_dev *dev, int new)
{
	spin_lock_irq(&dev->lock);
	dev->state = new;
	dev->in_progress = false;
	spin_unlock_irq(&dev->lock);
}

/*----------------------------------------------------------------------*/

static void usb_fuzzer_setup_log(const struct usb_ctrlrequest *ctrl, int vendor)
{
	print_debug("uf: usb_fuzzer_setup_log: bRequestType: 0x%x, bRequest: 0x%x, wValue: 0x%x, wIndex: 0x%x, wLength: %d\n",
		ctrl->bRequestType, ctrl->bRequest, ctrl->wValue, ctrl->wIndex, ctrl->wLength);

	switch (ctrl->bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		print_debug("uf: usb_fuzzer_setup_log: type = USB_TYPE_STANDARD\n");
		break;
	case USB_TYPE_CLASS:
		print_debug("uf: usb_fuzzer_setup_log: type = USB_TYPE_CLASS\n");
		break;
	case USB_TYPE_VENDOR:
		print_debug("uf: usb_fuzzer_setup_log: type = USB_TYPE_VENDOR\n");
		break;
	default:
		print_debug("uf: usb_fuzzer_setup_log: type = unknown = %d\n", (int)ctrl->bRequestType);
		break;
	}

	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS) {
		if (vendor == 0x08ca) { // USB_VENDOR_ID_AIPTEK
			switch (ctrl->bRequest) {
			case 0x01: // USB_REQ_GET_REPORT
				print_debug("uf: usb_fuzzer_setup_log: req = AIPTEK/USB_REQ_GET_REPORT\n");
				return;
			case 0x09: // USB_REQ_SET_REPORT
				print_debug("uf: usb_fuzzer_setup_log: req = AIPTEK/USB_REQ_SET_REPORT\n");
				return;
			}
		}
	}

	// HID class requests.
	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_GET_DESCRIPTOR\n");
			switch (ctrl->wValue >> 8) {
			case HID_DT_HID:
				print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = HID_DT_HID\n");
				return;
			case HID_DT_REPORT:
				print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = HID_DT_REPORT\n");
				return;
			case HID_DT_PHYSICAL:
				print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = HID_DT_PHYSICAL\n");
				return;
			}
		}
	}

	// CDC & HUB classes requests.
	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS) {
		switch (ctrl->bRequest) {
		case USB_CDC_GET_NTB_PARAMETERS:
			print_debug("uf: usb_fuzzer_setup_log: req = USB_CDC_GET_NTB_PARAMETERS\n");
			return;
		case USB_CDC_SET_CRC_MODE:
			print_debug("uf: usb_fuzzer_setup_log: req = USB_CDC_SET_CRC_MODE\n");
			return;
		case HUB_SET_DEPTH:
			print_debug("uf: usb_fuzzer_setup_log: req = HUB_SET_DEPTH\n");
			return;
		}
	}

	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_GET_DESCRIPTOR\n");
		switch (ctrl->wValue >> 8) {
		case USB_DT_DEVICE:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_DEVICE\n");
			break;
		case USB_DT_CONFIG:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_CONFIG, index = %d\n", (int)(ctrl->wValue & 0xff));
			break;
		case USB_DT_STRING:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_STRING\n");
			break;
		case USB_DT_INTERFACE:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_INTERFACE\n");
			break;
		case USB_DT_ENDPOINT:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_ENDPOINT\n");
			break;
		case USB_DT_DEVICE_QUALIFIER:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_DEVICE_QUALIFIER\n");
			break;
		case USB_DT_OTHER_SPEED_CONFIG:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_OTHER_SPEED_CONFIG\n");
			break;
		case USB_DT_INTERFACE_POWER:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_INTERFACE_POWER\n");
			break;
		case USB_DT_OTG:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_OTG\n");
			break;
		case USB_DT_DEBUG:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_DEBUG\n");
			break;
		case USB_DT_INTERFACE_ASSOCIATION:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_INTERFACE_ASSOCIATION\n");
			break;
		case USB_DT_SECURITY:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_SECURITY\n");
			break;
		case USB_DT_KEY:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_KEY\n");
			break;
		case USB_DT_ENCRYPTION_TYPE:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_ENCRYPTION_TYPE\n");
			break;
		case USB_DT_BOS:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_BOS\n");
			break;
		case USB_DT_DEVICE_CAPABILITY:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_DEVICE_CAPABILITY\n");
			break;
		case USB_DT_WIRELESS_ENDPOINT_COMP:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_WIRELESS_ENDPOINT_COMP\n");
			break;
		case USB_DT_WIRE_ADAPTER:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_WIRE_ADAPTER\n");
			break;
		case USB_DT_RPIPE:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_RPIPE\n");
			break;
		case USB_DT_CS_RADIO_CONTROL:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_CS_RADIO_CONTROL\n");
			break;
		case USB_DT_PIPE_USAGE:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_PIPE_USAGE\n");
			break;
		case USB_DT_SS_ENDPOINT_COMP:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_SS_ENDPOINT_COMP\n");
			break;
		case USB_DT_SSP_ISOC_ENDPOINT_COMP:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_SSP_ISOC_ENDPOINT_COMP\n");
			break;
		case USB_DT_HUB:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_HUB\n");
			break;
		case USB_DT_SS_HUB:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = USB_DT_SS_HUB\n");
			break;
		default:
			print_debug("uf: usb_fuzzer_setup_log: USB_REQ_GET_DESCRIPTOR: type = unknown = 0x%x\n", (int)(ctrl->wValue >> 8));
			break;
		}
		break;
	case USB_REQ_SET_CONFIGURATION:
		print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_SET_CONFIGURATION\n");
		break;
	case USB_REQ_GET_CONFIGURATION:
		print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_GET_CONFIGURATION\n");
		break;
	case USB_REQ_SET_INTERFACE:
		print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_SET_INTERFACE\n");
		break;
	case USB_REQ_GET_INTERFACE:
		print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_GET_INTERFACE\n");
		break;
	case USB_REQ_GET_STATUS:
		print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_GET_STATUS\n");
		break;
	case USB_REQ_CLEAR_FEATURE:
		print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_CLEAR_FEATURE\n");
		break;
	case USB_REQ_SET_FEATURE:
		print_debug("uf: usb_fuzzer_setup_log: req = USB_REQ_SET_FEATURE\n");
		break;
	default:
		print_debug("uf: usb_fuzzer_setup_log: req = unknown = 0x%x\n", (int)ctrl->bRequest);
		break;
	}
}

static void usb_fuzzer_setup(void *user_data, const struct usb_ctrlrequest *ctrl,
				struct usb_fuzzer_gadget_response *response)
{
	int ret = 0;
	struct fuzzer_dev *dev = (struct fuzzer_dev *)user_data;

	struct usb_device_descriptor *device;
	struct usb_config_descriptor *config;
	struct usb_interface_descriptor *iface;

	u16 vendor;

	struct usb_qualifier_descriptor *qual;
	struct response_map_entry *entry;
	unsigned power;
	u8 type;

	BUG_ON(!dev);

	print_debug("uf: usb_fuzzer_setup\n");

	device = (struct usb_device_descriptor *)dev->dev;
	config = (struct usb_config_descriptor *)(dev->dev + sizeof(*device));
	iface = (struct usb_interface_descriptor *)(dev->dev + sizeof(*device) + sizeof(*config));

	vendor = device->idVendor;
	usb_fuzzer_setup_log(ctrl, vendor);

	// For some random reason HID devices sometimes encode request class into the bRequest field,
	// so we have to handle for example HID_DT_REPORT in the handle_standard section.

	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD)
		goto handle_standard;
	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS)
		goto handle_class;
	if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_VENDOR)
		goto handle_vendor;

	BUG_ON(1);

handle_standard:
	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		switch (ctrl->wValue >> 8) {
			case USB_DT_DEVICE:
				print_debug("uf: usb_fuzzer_setup: replying to USB_REQ_GET_DESCRIPTOR/USB_DT_DEVICE\n");
				response->data = dev->dev;
				response->length = USB_DT_DEVICE_SIZE;
				goto out_respond;
			case USB_DT_CONFIG:
				print_debug("uf: usb_fuzzer_setup: replying to USB_REQ_GET_DESCRIPTOR/USB_DT_CONFIG\n");
				response->data = config;
				response->length = config->wTotalLength;
				goto out_respond;
			case USB_DT_STRING:
				print_debug("uf: usb_fuzzer_setup: replying to USB_REQ_GET_DESCRIPTOR/USB_DT_STRING\n");
				dev->buf[0] = 4;
				dev->buf[1] = USB_DT_STRING;
				if ((ctrl->wValue & 0xff) == 0) {
					dev->buf[2] = 0x09;
					dev->buf[3] = 0x04;
				} else {
					dev->buf[2] = 0x61;
					dev->buf[3] = 0x00;
				}
				response->data = dev->buf;
				response->length = 4;
				goto out_respond;
			case USB_DT_DEVICE_QUALIFIER:
				print_debug("uf: usb_fuzzer_setup: replying to USB_REQ_GET_DESCRIPTOR/USB_DT_DEVICE_QUALIFIER\n");
				device = (struct usb_device_descriptor *)dev->dev;
				qual = (struct usb_qualifier_descriptor *)dev->buf;
				qual->bLength = sizeof(*qual);
				qual->bDescriptorType = USB_DT_DEVICE_QUALIFIER;
				qual->bcdUSB = device->bcdUSB;
				qual->bDeviceClass = device->bDeviceClass;
				qual->bDeviceSubClass = device->bDeviceSubClass;
				qual->bDeviceProtocol = device->bDeviceProtocol;
				qual->bMaxPacketSize0 = device->bMaxPacketSize0;
				qual->bNumConfigurations = 1;
				qual->bRESERVED = 0;
				response->data = dev->buf;
				response->length = qual->bLength;
				goto out_respond;
		}
		break;
	case USB_REQ_SET_CONFIGURATION:
handle_set_configuration:
		print_debug("uf: usb_fuzzer_setup: replying to USB_REQ_SET_CONFIGURATION\n");
		config = (struct usb_config_descriptor *)(dev->dev + USB_DT_DEVICE_SIZE);
		power = config->bMaxPower ? config->bMaxPower : CONFIG_USB_GADGET_VBUS_DRAW;
		response->state = USB_STATE_CONFIGURED;
		response->power = power * 2;
		response->data = dev->buf;
		response->length = 0;
		goto out_respond;
	case USB_REQ_GET_CONFIGURATION:
		print_debug("uf: usb_fuzzer_setup: replying to USB_REQ_GET_CONFIGURATION\n");
		config = (struct usb_config_descriptor *)(dev->dev + USB_DT_DEVICE_SIZE);
		dev->buf[0] = config->bConfigurationValue;
		response->data = dev->buf;
		response->length = 0;
		goto out_respond;
	case USB_REQ_SET_INTERFACE:
		print_debug("uf: usb_fuzzer_setup: replying to USB_REQ_SET_INTERFACE\n");
		response->data = dev->buf;
		response->length = 0;
		goto out_respond;
	case USB_REQ_GET_INTERFACE:
handle_get_interface:
		dev->buf[0] = iface->bInterfaceNumber;
		response->data = dev->buf;
		response->length = 1;
		goto out_respond;
	}

	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		type = (u8)(ctrl->wValue >> 8);
		switch (type) {
		case USB_DT_BOS:
		case HID_DT_REPORT:
			goto get_from_map;
		}
		BUG_ON(1);
	}

	BUG_ON(1);

handle_class:
	switch (ctrl->bRequest) {
	case USB_REQ_GET_INTERFACE:
		goto handle_get_interface;
	case USB_REQ_SET_CONFIGURATION:
		goto handle_set_configuration;
	}

	if (vendor == 0x08ca) { // USB_VENDOR_ID_AIPTEK
		switch (ctrl->bRequest) {
		case 0x01: // USB_REQ_GET_REPORT
			goto get_from_map;
		case 0x09: // USB_REQ_SET_REPORT
			goto get_from_map;
		}
	}

	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		type = (u8)(ctrl->wValue >> 8);
		switch (type) {
		case USB_DT_HUB:
		case USB_DT_SS_HUB:
			goto get_from_map;
		}
		BUG_ON(1);
	case USB_REQ_GET_STATUS:
	case USB_REQ_CLEAR_FEATURE:
	case USB_REQ_SET_FEATURE:
	case USB_CDC_GET_NTB_PARAMETERS:
	case USB_CDC_SET_CRC_MODE:
	case HUB_SET_DEPTH:
	case 0x2b: // btusb driver
		goto get_from_map;
	}

	BUG_ON(1);

handle_vendor:
	goto get_from_map;

get_from_map:
	switch (ctrl->bRequest) {
	case USB_REQ_GET_DESCRIPTOR:
		type = (u8)(ctrl->wValue >> 8);
		entry = response_next(&dev->desc_responses, type);
		if (entry) {
			print_debug("uf: usb_fuzzer_setup: using desc response = 0x%x\n", (int)type);
			response->data = entry->data;
			response->length = entry->length;
			goto out_respond;
		}
	}

	type = ctrl->bRequest;
	entry = response_next(&dev->req_responses, type);
	if (entry) {
		print_debug("uf: usb_fuzzer_setup: using req response = 0x%x\n", (int)type);
		response->data = entry->data;
		response->length = entry->length;
		goto out_respond;
	}

	type = 0;
	entry = response_next(&dev->gen_responses, type);
	if (entry) {
		print_debug("uf: usb_fuzzer_setup: using gen response\n");
		response->data = entry->data;
		response->length = entry->length;
		goto out_respond;
	}

	print_debug("uf: usb_fuzzer_setup: replying with empty message\n");
	response->data = dev->buf;
	response->length = 0;

out_respond:
	print_debug("uf: usb_fuzzer_setup = %d\n", ret);
}

/*----------------------------------------------------------------------*/

static int fuzzer_open(struct inode *inode, struct file *fd)
{
	int ret = 0;
	struct fuzzer_dev *dev;

	print_debug("uf: fuzzer_open\n");

	dev = dev_new();
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}
	dev->state = STATE_DEV_OPENED;
	fd->private_data = dev;

out:
	print_debug("uf: fuzzer_open = %d\n", ret);
	return ret;
}

static int fuzzer_release(struct inode *inode, struct file *fd)
{
	int ret = 0;
	struct fuzzer_dev *dev = fd->private_data;

	print_debug("uf: fuzzer_release\n");

	if (!dev) {
		ret = -EBUSY;
		goto out;
	}
	if (dev->gadget) {
		usb_fuzzer_gadget_destroy(dev->gadget);
		dev->gadget = NULL;
	}
	dev_free(dev);

out:
	print_debug("uf: fuzzer_release = %d\n", ret);
	return ret;
}

#define USB_FUZZER_CMD_SETUP 100
#define USB_FUZZER_CMD_RUN 101

struct usb_fuzzer_setup_cmd {
	int64_t				speed;
	int64_t				length;
	char				*device;
	char				*desc_responses;
	char				*req_responses;
	char				*gen_responses;
};

static int check_device(char *data, u64 length)
{
	struct usb_device_descriptor *device;
	struct usb_config_descriptor *config;
	struct usb_interface_descriptor *iface;

	device = (struct usb_device_descriptor *)data;
	config = (struct usb_config_descriptor *)(data + sizeof(*device));
	iface = (struct usb_interface_descriptor *)(data + sizeof(*device) + sizeof(*config));

	if (length < sizeof(struct usb_device_descriptor) + sizeof(struct usb_config_descriptor))
		return -EINVAL;
	if (config->wTotalLength < sizeof(*config) + sizeof(*iface))
		return -EINVAL;
	if (length < sizeof(*device) + config->wTotalLength)
		return -EINVAL;

	print_debug("uf: check_device: idVendor: 0x%04x, idProduct: 0x%04x\n", (int)device->idVendor, (int)device->idProduct);
	print_debug("uf: check_device: bDeviceClass: 0x%x, bInterfaceClass: 0x%x\n", device->bDeviceClass, iface->bInterfaceClass);

	return 0;
}

static long fuzzer_ioctl_setup(struct fuzzer_dev *dev, unsigned long value)
{
	long ret = 0;
	struct usb_fuzzer_gadget_info info;
	struct usb_fuzzer_setup_cmd cmd;
	u64 length;

	print_debug("uf: fuzzer_ioctl_setup\n");

	ret = dev_acquire_state(dev, STATE_DEV_OPENED);
	if (ret < 0)
		goto out;

	print_debug("uf: fuzzer_ioctl_setup: getting cmd\n");
	if (copy_from_user(&cmd, (void *)value, sizeof(cmd))) {
		ret = -EFAULT;
		goto out;
	}
	print_debug("uf: fuzzer_ioctl_setup: got cmd\n");

	print_debug("uf: fuzzer_ioctl_setup: getting device descriptor\n");
	if (cmd.length < 0 || cmd.length > 0x4000) {
		ret = -EINVAL;
		goto out;
	}
	dev->dev = memdup_user(cmd.device, cmd.length);
	if (IS_ERR(dev->dev)) {
		ret = PTR_ERR(dev->dev);
		dev->dev = NULL;
		goto out;
	}
	ret = check_device(dev->dev, cmd.length);
	if (ret)
		goto out;
	print_debug("uf: fuzzer_ioctl_setup: device descriptor ok\n");

	print_debug("uf: fuzzer_ioctl_setup: unpacking desc responses\n");
	if (copy_from_user(&length, cmd.desc_responses, sizeof(length))) {
		ret = -EFAULT;
		goto out;
	}
	ret = response_unpack(&dev->desc_responses, cmd.desc_responses + sizeof(length), length);
	if (ret)
		goto out;
	print_debug("uf: fuzzer_ioctl_setup: unpacking done\n");

	print_debug("uf: fuzzer_ioctl_setup: unpacking req responses\n");
	if (copy_from_user(&length, cmd.req_responses, sizeof(length))) {
		ret = -EFAULT;
		goto out;
	}
	ret = response_unpack(&dev->req_responses, cmd.req_responses + sizeof(length), length);
	if (ret)
		goto out;
	print_debug("uf: fuzzer_ioctl_setup: unpacking done\n");

	print_debug("uf: fuzzer_ioctl_setup: unpacking gen responses\n");
	if (copy_from_user(&length, cmd.gen_responses, sizeof(length))) {
		ret = -EFAULT;
		goto out;
	}
	ret = response_unpack(&dev->gen_responses, cmd.gen_responses + sizeof(length), length);
	if (ret)
		goto out;
	print_debug("uf: fuzzer_ioctl_setup: unpacking done\n");

	dev->buf = kmalloc(128, GFP_KERNEL);
	if (!dev->buf) {
		ret = -ENOMEM;
		goto out;
	}

	info.speed = cmd.speed;
	info.user_data = dev;
	info.setup = usb_fuzzer_setup;
	dev->gadget = usb_fuzzer_gadget_init(&info);
	if (IS_ERR(dev->gadget)) {
		ret = PTR_ERR(dev->gadget);
		dev->gadget = NULL;
		goto out;
	}

out:
	if (ret != 0)
		dev_release_state(dev, STATE_DEV_FAILED);
	else
		dev_release_state(dev, STATE_DEV_SETUP);
	print_debug("uf: fuzzer_ioctl_setup = %ld\n", ret);
	return ret;
}

static long fuzzer_ioctl_run(struct fuzzer_dev *dev, unsigned long value)
{
	long ret = 0;

	print_debug("uf: fuzzer_ioctl_run\n");

	ret = dev_acquire_state(dev, STATE_DEV_SETUP);
	if (ret < 0)
		goto out;
	ret = usb_fuzzer_gadget_run(dev->gadget);
	if (ret != 0)
		dev_release_state(dev, STATE_DEV_FAILED);
	else
		dev_release_state(dev, STATE_DEV_RUNNING);

out:
	print_debug("uf: fuzzer_ioctl_run = %ld\n", ret);
	return ret;
}

static long fuzzer_ioctl(struct file *fd, unsigned cmd, unsigned long value)
{
	struct fuzzer_dev *dev = fd->private_data;
	long ret;

	print_debug("uf: fuzzer_ioctl: cmd: %u, value: %lx\n", cmd, value);

	if (!dev) {
		ret = -EBUSY;
		goto out;
	}
	switch (cmd) {
	case USB_FUZZER_CMD_SETUP:
		ret = fuzzer_ioctl_setup(dev, value);
		break;
	case USB_FUZZER_CMD_RUN:
		ret = fuzzer_ioctl_run(dev, value);
		break;
	default:
		ret = -EINVAL;
	}

out:
	print_debug("uf: fuzzer_ioctl = %ld\n", ret);
	return ret;
}

/*----------------------------------------------------------------------*/

static const struct file_operations fuzzer_ops = {
	.open =			fuzzer_open,
	.unlocked_ioctl =	fuzzer_ioctl,
	.release =		fuzzer_release,
	.llseek =		no_llseek,
};

static int __init fuzzer_init(void)
{
	/*
	 * The usb-fuzzer debugfs file won't ever get removed and thus,
	 * there is no need to protect it against removal races. The
	 * use of debugfs_create_file_unsafe() is actually safe here.
	 */
	if (!debugfs_create_file_unsafe("usb-fuzzer", 0600, NULL, NULL, &fuzzer_ops)) {
		print_debug("failed to create usb-fuzzer in debugfs\n");
		return -ENOMEM;
	}
	return 0;
}

device_initcall(fuzzer_init);
